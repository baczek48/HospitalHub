"""In-process SSH+SFTP server over socket.socketpair() (no network) — test helper.

Ported from the 2026-10-16 UX audit (A4).  Not a test module itself.

FakeServer(root).client()  -> a connected paramiko.SSHClient
server.drop()              -> kill every connection (link lost)
extra_names: list of bytes filenames injected into every listing of '/'.
"""
import os, socket, threading, time
import paramiko
from paramiko import (AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED, SFTP_OK, ServerInterface,
                      SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface)

_HOST_KEY = None


def host_key():
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(1024)
    return _HOST_KEY


class _Handle(SFTPHandle):
    delay = 0.0

    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))

    def read(self, offset, length):
        if self.delay:
            time.sleep(self.delay)
        return super().read(offset, length)

    def write(self, offset, data):
        if self.delay:
            time.sleep(self.delay)
        return super().write(offset, data)

    def chattr(self, attr):
        return SFTP_OK


def make_sftp_class(srv):
    class _Sftp(SFTPServerInterface):
        def _real(self, path):
            return os.path.join(srv.root, *[p for p in path.split("/") if p])

        def canonicalize(self, path):
            if not path.startswith("/"):
                path = "/" + path
            parts = []
            for p in path.split("/"):
                if p in ("", "."):
                    continue
                if p == "..":
                    if parts:
                        parts.pop()
                    continue
                parts.append(p)
            return "/" + "/".join(parts)

        def list_folder(self, path):
            if srv.list_delay:
                time.sleep(srv.list_delay)
            real = self._real(path)
            try:
                out = []
                for n in os.listdir(real):
                    a = SFTPAttributes.from_stat(os.stat(os.path.join(real, n)))
                    a.filename = n
                    out.append(a)
                if path in ("/", "") and srv.extra_names:
                    for raw in srv.extra_names:
                        a = SFTPAttributes()
                        a.st_size, a.st_mode, a.st_mtime = 10, 0o100644, int(time.time())
                        a.st_uid = a.st_gid = 0
                        a.filename = raw       # bytes => sent verbatim
                        out.append(a)
                if srv.fake_count and path.rstrip("/").endswith("big"):
                    now = int(time.time())
                    for i in range(srv.fake_count):
                        a = SFTPAttributes()
                        a.st_size, a.st_mode, a.st_mtime = i, 0o100644, now
                        a.st_uid = a.st_gid = 0
                        a.filename = f"plik_{i:06d}.hl7"
                        out.append(a)
                return out
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)

        def stat(self, path):
            if path.rstrip("/").endswith("big") and srv.fake_count:
                a = SFTPAttributes(); a.st_mode = 0o040755; a.st_size = 0
                return a
            try:
                return SFTPAttributes.from_stat(os.stat(self._real(path)))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)

        lstat = stat

        def open(self, path, flags, attr):
            real = self._real(path)
            try:
                fd = os.open(real, flags | getattr(os, "O_BINARY", 0), 0o666)
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            mode = "wb" if flags & os.O_WRONLY else ("r+b" if flags & os.O_RDWR else "rb")
            h = _Handle(flags)
            h.delay = srv.io_delay
            h.filename = real
            h.readfile = h.writefile = os.fdopen(fd, mode)
            return h

        def remove(self, path):
            try:
                os.remove(self._real(path))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return SFTP_OK

        def rename(self, old, new):
            try:
                os.rename(self._real(old), self._real(new))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return SFTP_OK

        posix_rename = rename

        def mkdir(self, path, attr):
            try:
                os.mkdir(self._real(path))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return SFTP_OK

        def rmdir(self, path):
            try:
                os.rmdir(self._real(path))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return SFTP_OK

        def chattr(self, path, attr):
            return SFTP_OK
    return _Sftp


class _Iface(ServerInterface):
    def __init__(self, srv):
        self.srv = srv

    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL if password == self.srv.password else AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_x11_request(self, *a):
        return False

    def check_channel_window_change_request(self, channel, w, h, pw, ph):
        self.srv.resizes.append((w, h))
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.srv._shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        def run():
            channel.sendall(b"0.42\n512/2048\n1d 02h 03m\n37 10G/27G\n")
            channel.send_exit_status(0)
            channel.close()
        threading.Thread(target=run, daemon=True).start()
        return True


class FakeServer:
    def __init__(self, root, password="pw"):
        self.root = root
        self.password = password
        self.extra_names = []
        self.fake_count = 0
        self.list_delay = 0.0
        self.io_delay = 0.0
        self.resizes = []
        self.socks = []
        self.transports = []
        self.connects = 0
        self.refuse = False

    def _shell(self, chan):
        try:
            chan.send(b"Welcome to fake host\r\n$ ")
            buf = b""
            while not chan.closed:
                d = chan.recv(1024)
                if not d:
                    break
                chan.send(d)
                buf += d
                if b"\r" in buf:
                    line, _, buf = buf.partition(b"\r")
                    if line.strip() == b"exit":
                        chan.send_exit_status(0)
                        chan.close()
                        return
                    if line.strip() == b"flood":
                        for i in range(20000):
                            chan.send(b"2026-10-16 12:00:00 INFO linia logu %d\r\n" % i)
                    chan.send(b"\r\n$ ")
        except Exception:
            pass

    def client(self):
        if self.refuse:
            raise OSError(10061, "Connection refused (fake)")
        self.connects += 1
        s_sock, c_sock = socket.socketpair()
        self.socks.append(s_sock)
        st = paramiko.Transport(s_sock)
        st.add_server_key(host_key())
        st.set_subsystem_handler("sftp", SFTPServer, make_sftp_class(self))
        self.transports.append(st)
        threading.Thread(target=lambda: st.start_server(server=_Iface(self)), daemon=True).start()
        ct = paramiko.Transport(c_sock)
        ct.connect(username="u", password=self.password)
        c = paramiko.SSHClient()
        c._transport = ct
        return c

    def make_client_patch(self):
        def _mk(host, user, password, port=22):
            if self.refuse:
                raise OSError(10061, "Connection refused (fake)")
            if password != self.password:
                raise paramiko.AuthenticationException("bad")
            return self.client()
        return _mk

    def drop(self):
        for s in self.socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        for t in self.transports:
            try:
                t.close()
            except Exception:
                pass
        self.socks.clear()
        self.transports.clear()
