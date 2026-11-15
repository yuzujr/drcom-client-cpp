"""Black-box fault injection; no production mock/codec dependencies."""
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

CLIENT = str(Path(sys.argv[1]).resolve())


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.03)
    raise AssertionError('Timed out waiting for recovery')


class Server:
    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.challenges = 0
        self.logins = 0
        self.maintenance = 0
        self.error = None
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    data, peer = self.sock.recvfrom(65535)
                except socket.timeout:
                    continue
                kind = data[0]
                if kind == 1:
                    self.challenges += 1
                    response = b'\x02\x02\0\0salt'
                    if self.mode == 'truncated_challenge' and self.challenges == 1:
                        response = b'\x02'
                elif kind == 3:
                    self.logins += 1
                    if self.mode == 'reject':
                        response = b'\x04\x01'
                    elif self.mode == 'truncated_login' and self.logins == 1:
                        response = b'\x04\0'
                    elif self.mode == 'noise':
                        # A complete old challenge response cannot satisfy login.
                        response = b'\x02\x02\0\0salt'
                    else:
                        response = b'\x04\0' + bytes(37)
                        if self.mode == 'stale':
                            self.sock.sendto(b'\x02\x02\0\0salt', peer)
                elif kind in (7, 255):
                    self.maintenance += 1
                    if self.mode == 'drop' and self.logins == 1:
                        continue
                    response = b'\x07\0' + bytes(18)
                    if self.mode == 'stale':
                        self.sock.sendto(b'\x04\0' + bytes(37), peer)
                elif kind == 6:
                    response = b'\x05\0'
                else:
                    raise AssertionError(f'Unexpected client packet: {kind}')
                self.sock.sendto(response, peer)
        except BaseException as error:
            self.error = error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive(), 'Server thread leaked'
        self.sock.close()
        if self.error:
            raise self.error


def scenario(mode):
    server = Server(mode)
    process = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            config = root / 'test.conf'
            config.write_text(f'''username=test_user
password=test_pass
ip=127.0.0.1
mac=4c:44:5b:00:81:24
server_ip=127.0.0.1
server_port={server.port}
client_ip=127.0.0.1
client_port={port}
auto_identity=false
reconnect_interval=1
auth_interval=1
heartbeat_interval=1
debug=true
''')
            with (root / 'client.log').open('w') as log:
                process = subprocess.Popen([CLIENT, '-c', str(config), '--state-dir', str(state)],
                                           stdout=log, stderr=subprocess.STDOUT)
                def command(name):
                    return subprocess.check_output([CLIENT, name, '--state-dir', str(state)],
                                                   text=True, timeout=3)
                def healthy():
                    assert process.poll() is None, (root / 'client.log').read_text()
                    return 'State: authenticated' in command('status') and server.maintenance >= 2
                try:
                    if mode == 'reject':
                        assert process.wait(timeout=4) == 1, 'Explicit refusal must be fatal'
                        assert server.logins == 1, 'Retried an explicit authentication refusal'
                        assert 'Authentication rejected' in command('status')
                    elif mode == 'noise':
                        wait_for(lambda: server.logins >= 1)
                        assert 'State: authenticated' not in command('status')
                        started = time.monotonic()
                        command('disable')
                        wait_for(lambda: 'State: disabled' in command('status'), 1)
                        assert time.monotonic() - started < 1, 'Old response prevented cancellation'
                    else:
                        if mode in ('truncated_login', 'truncated_challenge', 'drop'):
                            wait_for(lambda: server.challenges >= 2, 10)
                        wait_for(healthy)
                        if mode == 'stale':
                            time.sleep(2.2)
                            assert healthy()
                            assert server.logins == 1, 'Stale packets triggered reauthentication'
                        command('disable')
                        wait_for(lambda: 'State: disabled' in command('status'), 1)
                        packets = server.maintenance
                        time.sleep(0.2)
                        assert server.maintenance == packets, 'Traffic after disable acknowledgement'
                except BaseException:
                    print((root / 'client.log').read_text(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=3)
                    text = (root / 'client.log').read_text()
                    for private in ('test_user', 'test_pass', '74 65 73 74 5f 75 73 65 72', 'Login salt'):
                        assert private not in text, f'Private data in debug logs: {private}'
        print(f'{mode}: passed')
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        server.close()


if __name__ == '__main__':
    for mode in ('truncated_challenge', 'truncated_login', 'drop', 'stale', 'reject', 'noise'):
        scenario(mode)
