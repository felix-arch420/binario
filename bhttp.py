#!/usr/bin/env python3
# Servidor BHTTP autónomo.
# Protocolo original de 29 bytes intacto.
#
# Prueba de streaming:
# - Cada chunk del modo batch tiene su propio LONGPOLL.
# - El resto de la lógica se conserva igual.

import argparse
import asyncio
import hashlib
import sys
import socket
import time
from contextlib import suppress


MAGIC = b"BHP1"
LONGPOLL = 2.0

DEFAULT_MAX_SESSIONS = 512
DEFAULT_SESSION_IDLE = 120.0

MAX_PAYLOAD = 4 * 1024 * 1024
MAX_PROBE_SIZE = 64 * 1024

MAX_DOWN_RAW = 8 * 1024 * 1024
READ_PAUSE_HI = 6 * 1024 * 1024
READ_PAUSE_LO = 2 * 1024 * 1024

MAX_DOWN_CHUNKS = 256
CHUNK_TTL = 60.0

MAX_UP_WINDOW = 1024
MAX_UP_PENDING = 1024

MAX_CHUNK_SIZE = 512 * 1024
MAX_BATCH_COUNT = 16
BACKEND_READ_SIZE = 262144

HANDSHAKE_TIMEOUT = 30.0
ZOMBIE_IDLE = 300.0

LOG_LEVEL = 1
LOG_T0 = time.monotonic()


def log(msg, level=1):
    if level > LOG_LEVEL:
        return
    elapsed = time.monotonic() - LOG_T0
    sys.stderr.write(f"[bhttp-pro {elapsed:8.2f}s] {msg}\n")
    sys.stderr.flush()


def keystream(sess, mode, seq, direction, size):
    base = hashlib.sha256(
        sess + bytes([mode])
        + seq.to_bytes(8, "big")
        + bytes([direction])
    )

    output = bytearray()
    counter = 0

    while len(output) < size:
        h = base.copy()
        h.update(counter.to_bytes(4, "big"))
        output.extend(h.digest())
        counter += 1

    return bytes(output[:size])


def mask(data, sess, mode, seq, direction):
    if not data:
        return b""

    stream = keystream(
        sess, mode, seq, direction, len(data)
    )

    return bytes(a ^ b for a, b in zip(data, stream))


def probe_reply(mode, size):
    size = min(size, MAX_PROBE_SIZE)
    n = size if mode == 2 and size >= 10 else 10

    output = bytearray(
        MAGIC + bytes([1, mode]) + size.to_bytes(4, "big")
    )

    for i in range(10, n):
        output.append((i * 31) & 255)

    return bytes(output)


def optimize_socket(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)
    except OSError:
        pass


class Session:

    def __init__(self, sess, backend):
        self.sess = sess
        self.backend = backend

        self.cond = asyncio.Condition()
        self.write_lock = asyncio.Lock()

        self.up_next = 0
        self.up_pending = {}

        self.down_raw = bytearray()
        self.down_chunks = {}
        self.down_assign = 0

        self.eof = False
        self.closed = False

        self.br = None
        self.bw = None
        self.reader_task = None

        now = time.monotonic()
        self.last_active = now
        self.last_data = now

        self.reader_resume = asyncio.Event()
        self.reader_resume.set()

    def touch(self, data=False):
        now = time.monotonic()
        self.last_active = now
        if data:
            self.last_data = now

    async def connect(self):
        host, port = self.backend
        self.br, self.bw = await asyncio.open_connection(host, port)

        sock = self.bw.get_extra_info("socket")
        if sock:
            optimize_socket(sock)

        self.reader_task = asyncio.create_task(self._reader())

    async def _reader(self):
        try:
            while not self.closed:

                while True:
                    async with self.cond:
                        if self.closed:
                            return

                        if len(self.down_raw) < READ_PAUSE_HI:
                            break

                        self.reader_resume.clear()

                    await self.reader_resume.wait()

                if self.closed:
                    break

                async with self.cond:
                    available = MAX_DOWN_RAW - len(self.down_raw)

                    if available <= 0:
                        self.reader_resume.clear()
                        continue

                    read_size = min(
                        BACKEND_READ_SIZE,
                        available
                    )

                data = await self.br.read(read_size)

                if not data:
                    break

                async with self.cond:
                    if self.closed:
                        break

                    self.down_raw.extend(data)
                    self.touch(data=True)
                    self.cond.notify_all()

        except asyncio.CancelledError:
            raise

        except Exception as e:
            log(
                f"reader error {self.sess.hex()[:8]}: {e!r}",
                level=2
            )

        finally:
            async with self.cond:
                self.eof = True
                self.reader_resume.set()
                self.cond.notify_all()

    async def upload(self, seq, data):
        async with self.cond:
            if self.closed:
                return False

            if seq > self.up_next + MAX_UP_WINDOW:
                return False

            if (
                len(self.up_pending) >= MAX_UP_PENDING
                and seq not in self.up_pending
            ):
                return False

            if data:
                self.up_pending[seq] = data

            to_write = []

            while self.up_next in self.up_pending:
                to_write.append(
                    self.up_pending.pop(self.up_next)
                )
                self.up_next += 1

            self.touch(data=bool(to_write))

        if not to_write:
            return True

        async with self.write_lock:
            for chunk in to_write:
                if self.closed:
                    return False

                try:
                    self.bw.write(chunk)
                    await self.bw.drain()

                except Exception:
                    async with self.cond:
                        self.closed = True
                        self.eof = True
                        self.reader_resume.set()
                        self.cond.notify_all()
                    return False

        return True

    def _cleanup_expired_chunks_locked(self, now):
        expired = [
            key for key, (_, timestamp)
            in self.down_chunks.items()
            if now - timestamp > CHUNK_TTL
        ]

        for key in expired:
            del self.down_chunks[key]

    async def download(self, seq, maxlen, deadline):
        maxlen = max(
            1,
            min(maxlen or 65536, MAX_CHUNK_SIZE)
        )

        loop = asyncio.get_running_loop()

        async with self.cond:
            while True:

                if self.closed:
                    return b""

                if seq < self.down_assign:
                    record = self.down_chunks.get(seq)
                    return record[0] if record else b""

                if seq == self.down_assign:

                    if self.down_raw:
                        take_len = min(
                            len(self.down_raw),
                            maxlen
                        )

                        chunk = bytes(
                            self.down_raw[:take_len]
                        )
                        del self.down_raw[:take_len]

                        if len(self.down_raw) <= READ_PAUSE_LO:
                            self.reader_resume.set()

                        now = loop.time()
                        self._cleanup_expired_chunks_locked(now)

                        while len(self.down_chunks) >= MAX_DOWN_CHUNKS:
                            oldest = min(
                                self.down_chunks,
                                key=lambda key:
                                self.down_chunks[key][1]
                            )
                            del self.down_chunks[oldest]

                        self.down_chunks[seq] = (chunk, now)
                        self.down_assign += 1

                        self.touch(data=True)
                        self.cond.notify_all()

                        return chunk

                    if self.eof:
                        self.down_assign += 1
                        self.touch()
                        self.cond.notify_all()
                        return b""

                remaining = deadline - loop.time()

                if self.eof or remaining <= 0:
                    while self.down_assign <= seq:
                        self.down_assign += 1

                    self.touch()
                    self.cond.notify_all()
                    return b""

                try:
                    await asyncio.wait_for(
                        self.cond.wait(),
                        timeout=max(0.005, remaining)
                    )
                except asyncio.TimeoutError:
                    pass

    async def ack(self, seq):
        now = time.monotonic()

        async with self.cond:
            remove = [
                key for key, (_, timestamp)
                in self.down_chunks.items()
                if key <= seq or now - timestamp > CHUNK_TTL
            ]

            for key in remove:
                del self.down_chunks[key]

            self.touch(data=False)
            self.cond.notify_all()

    async def close(self):
        async with self.cond:
            if self.closed:
                return

            self.closed = True
            self.eof = True
            self.reader_resume.set()
            self.cond.notify_all()

        current = asyncio.current_task()

        if (
            self.reader_task
            and self.reader_task is not current
            and not self.reader_task.done()
        ):
            self.reader_task.cancel()

            with suppress(
                asyncio.CancelledError,
                Exception
            ):
                await self.reader_task

        if self.bw:
            try:
                self.bw.close()
                with suppress(Exception):
                    await self.bw.wait_closed()
            except Exception:
                pass


class Server:

    def __init__(
        self,
        host,
        port,
        backend,
        max_sessions=DEFAULT_MAX_SESSIONS,
        session_idle=DEFAULT_SESSION_IDLE
    ):
        self.host = host
        self.port = port
        self.backend = backend

        self.max_sessions = max_sessions
        self.session_idle = session_idle

        self.sessions = {}
        self.slock = asyncio.Lock()

        self.reaper_task = None
        self.stats_task = None

        self.stat_conns = 0
        self.stat_sessions_total = 0
        self.stat_bytes_up = 0
        self.stat_bytes_down = 0

    async def get_session(self, sess):
        victim = None

        async with self.slock:
            session = self.sessions.get(sess)

            if session and not session.closed:
                session.touch()
                return session

            if session:
                del self.sessions[sess]

            if len(self.sessions) >= self.max_sessions:
                victim_key, victim = min(
                    self.sessions.items(),
                    key=lambda item: item[1].last_active
                )
                del self.sessions[victim_key]

            session = Session(sess, self.backend)
            self.sessions[sess] = session
            self.stat_sessions_total += 1

        if victim:
            await victim.close()

        try:
            await session.connect()
        except Exception:
            async with self.slock:
                if self.sessions.get(sess) is session:
                    del self.sessions[sess]
            await session.close()
            raise

        return session

    async def _reap(self):
        while True:
            await asyncio.sleep(15)

            now = time.monotonic()
            victims = []

            async with self.slock:
                for key, session in list(self.sessions.items()):
                    idle = now - session.last_active
                    zombie = now - session.last_data

                    if (
                        session.closed
                        or idle > self.session_idle
                        or zombie > ZOMBIE_IDLE
                    ):
                        victims.append(session)
                        del self.sessions[key]

            for session in victims:
                await session.close()

    async def _stats(self):
        while True:
            await asyncio.sleep(60)

            log(
                f"stats: sesiones={len(self.sessions)} "
                f"conns={self.stat_conns} "
                f"sess_total={self.stat_sessions_total} "
                f"up={self.stat_bytes_up}B "
                f"down={self.stat_bytes_down}B",
                level=2
            )

    async def handle(self, reader, writer):
        sock = writer.get_extra_info("socket")
        if sock:
            optimize_socket(sock)

        self.stat_conns += 1
        first_header = True

        try:
            while True:

                if first_header:
                    try:
                        hdr = await asyncio.wait_for(
                            reader.readexactly(29),
                            timeout=HANDSHAKE_TIMEOUT
                        )
                    except asyncio.TimeoutError:
                        return

                    first_header = False
                else:
                    hdr = await reader.readexactly(29)

                mode = hdr[0]
                sess = hdr[1:17]
                seq = int.from_bytes(hdr[17:25], "big")
                ln = int.from_bytes(hdr[25:29], "big")

                if ln > MAX_PAYLOAD:
                    return

                payload = b""

                if ln and mode in (0, 1, 2, 3):
                    raw = await reader.readexactly(ln)
                    payload = mask(
                        raw, sess, mode, seq, 0
                    )

                    if mode == 1:
                        self.stat_bytes_up += len(payload)

                if payload[:4] == MAGIC:
                    size = (
                        int.from_bytes(payload[6:10], "big")
                        if len(payload) >= 10 else 0
                    )

                    pmode = (
                        payload[5]
                        if len(payload) >= 6 else mode
                    )

                    body = mask(
                        probe_reply(pmode, size),
                        sess, mode, seq, 1
                    )

                    writer.write(
                        bytes([0])
                        + len(body).to_bytes(4, "big")
                        + body
                    )
                    await writer.drain()
                    continue

                if mode == 0:
                    writer.write(
                        bytes([0])
                        + (0).to_bytes(4, "big")
                    )
                    await writer.drain()
                    continue

                session = await self.get_session(sess)

                if mode == 1:
                    await session.upload(seq, payload)

                    writer.write(
                        bytes([0])
                        + (0).to_bytes(4, "big")
                    )
                    await writer.drain()

                elif mode == 2:
                    deadline = (
                        asyncio.get_running_loop().time()
                        + LONGPOLL
                    )

                    chunk = await session.download(
                        seq,
                        ln if ln > 0 else 65536,
                        deadline
                    )

                    self._send_data(
                        writer, sess, mode, seq, chunk
                    )
                    await writer.drain()

                elif mode == 3:
                    if len(payload) >= 6:
                        chunk_size = int.from_bytes(
                            payload[0:4], "big"
                        )
                        count = payload[5]
                    else:
                        chunk_size = 65536
                        count = 4

                    chunk_size = max(
                        1,
                        min(chunk_size, MAX_CHUNK_SIZE)
                    )

                    count = max(
                        1,
                        min(count, MAX_BATCH_COUNT)
                    )

                    # CAMBIO DE PRUEBA:
                    # Cada chunk obtiene su propio LONGPOLL.
                    for i in range(count):

                        deadline = (
                            asyncio.get_running_loop().time()
                            + LONGPOLL
                        )

                        chunk = await session.download(
                            seq + i,
                            chunk_size,
                            deadline
                        )

                        self._send_data(
                            writer,
                            sess,
                            mode,
                            seq + i,
                            chunk
                        )

                    await writer.drain()

                elif mode == 4:
                    await session.ack(seq)

                    writer.write(
                        bytes([0])
                        + (0).to_bytes(4, "big")
                    )
                    await writer.drain()

                else:
                    return

        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError
        ):
            pass

        except Exception as e:
            log(
                f"handle error: {e!r}",
                level=2
            )

        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    def _send_data(
        self,
        writer,
        sess,
        mode,
        seq,
        data
    ):
        real = len(data)

        masked = (
            mask(data, sess, mode, seq, 1)
            if data else b""
        )

        body = real.to_bytes(4, "big") + masked
        self.stat_bytes_down += real

        writer.write(
            bytes([2])
            + len(body).to_bytes(4, "big")
            + body
        )

    async def serve(self):
        server = await asyncio.start_server(
            self.handle,
            self.host,
            self.port,
            backlog=8192
        )

        self.reaper_task = asyncio.create_task(
            self._reap()
        )
        self.stats_task = asyncio.create_task(
            self._stats()
        )

        log(
            f"escuchando en {self.host}:{self.port} "
            f"-> {self.backend[0]}:{self.backend[1]}"
        )

        try:
            async with server:
                await server.serve_forever()

        finally:
            for task in (
                self.reaper_task,
                self.stats_task
            ):
                if task:
                    task.cancel()

                    with suppress(
                        asyncio.CancelledError,
                        Exception
                    ):
                        await task

            async with self.slock:
                sessions = list(self.sessions.values())
                self.sessions.clear()

            for session in sessions:
                await session.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        default="0.0.0.0"
    )
    parser.add_argument(
        "--port",
        type=int,
        required=True
    )
    parser.add_argument(
        "--backend-host",
        default="127.0.0.1"
    )
    parser.add_argument(
        "--backend-port",
        type=int,
        default=22
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=DEFAULT_MAX_SESSIONS
    )
    parser.add_argument(
        "--session-idle",
        type=float,
        default=DEFAULT_SESSION_IDLE
    )
    parser.add_argument(
        "--log-level",
        type=int,
        default=1,
        choices=[0, 1, 2]
    )

    args = parser.parse_args()

    global LOG_LEVEL
    LOG_LEVEL = args.log_level

    asyncio.run(
        Server(
            args.host,
            args.port,
            (
                args.backend_host,
                args.backend_port
            ),
            max_sessions=args.max_sessions,
            session_idle=args.session_idle,
        ).serve()
    )


if __name__ == "__main__":
    main()