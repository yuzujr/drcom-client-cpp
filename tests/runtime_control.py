"""Check CLI persistence, cancellation during login, and pause without logout."""
from pathlib import Path
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

client_exe, server_exe = sys.argv[1:3]
processes = []


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    return sock


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for state')


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    state = root / 'state'

    def command(name):
        return subprocess.check_output([client_exe, name, '--state-dir', str(state)], text=True)

    def launch(port):
        reserved = udp()
        client_port = reserved.getsockname()[1]
        reserved.close()
        config = root / 'test.conf'
        config.write_text(f'''username=test_user
password=test_pass
ip=127.0.0.1
mac=4c:44:5b:00:81:24
server_ip=127.0.0.1
server_port={port}
client_ip=127.0.0.1
client_port={client_port}
auto_identity=false
auth_interval=2
heartbeat_interval=2
''')
        log = root / f'client-{len(processes)}.log'
        with log.open('w') as output:
            process = subprocess.Popen([client_exe, '-c', str(config), '--state-dir', str(state)], stdout=output, stderr=subprocess.STDOUT)
        processes.append(process)
        return process, log

    try:
        with udp() as silent:
            process, log = launch(silent.getsockname()[1])
            assert select.select([silent], [], [], 2)[0], 'No handshake request'
            silent.recvfrom(4096)
            assert 'State: authenticating' in command('status')
            start = time.monotonic()
            command('disable')
            wait_for(lambda: 'disabled; waiting' in log.read_text(), 1)
            assert time.monotonic() - start < 1
            assert process.poll() is None
            assert 'disabled' in command('status')
            assert 'State: disabled' in command('status')
            assert not select.select([silent], [], [], 0.4)[0], 'Sent while disabled'
            command('enable')
            assert select.select([silent], [], [], 1)[0], 'Enable did not resume handshake'
            silent.recvfrom(4096)
            start = time.monotonic()
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=1) == 0
            assert time.monotonic() - start < 1, 'Shutdown blocked on 15s timeout'
            assert 'Runtime: not running' in command('status')
            command('disable')
            process, log = launch(silent.getsockname()[1])
            wait_for(lambda: 'disabled; waiting' in log.read_text())
            assert not select.select([silent], [], [], 0.4)[0], 'Lost disabled state on restart'
            process.terminate()
            assert process.wait(timeout=1) == 0
        command('enable')
        reserved = udp()
        port = reserved.getsockname()[1]
        reserved.close()
        server_log = root / 'server.log'
        with server_log.open('w') as output:
            server = subprocess.Popen([server_exe, str(port)], stdout=output, stderr=subprocess.STDOUT)
        processes.append(server)
        wait_for(lambda: 'listening' in server_log.read_text())
        process, log = launch(port)
        wait_for(lambda: 'Connected successfully' in log.read_text())
        assert 'State: authenticated' in command('status')
        # A second publisher must not overwrite the live daemon's status.
        duplicate = subprocess.run([client_exe, '-c', str(root / 'test.conf'), '--state-dir', str(state)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert duplicate.returncode == 1 and 'runtime lock' in duplicate.stdout
        assert 'State: authenticated' in command('status')
        command('disable')
        wait_for(lambda: 'disabled; waiting' in log.read_text())
        time.sleep(0.2)
        previous = server_log.read_text()
        time.sleep(1)
        assert server_log.read_text() == previous, 'Traffic continued while paused'
        assert 'Client logged out' not in previous, 'Disable sent logout'
        assert process.poll() is None
        command('enable')
        wait_for(lambda: log.read_text().count('Connected successfully') == 2)
        command('disable')
        wait_for(lambda: log.read_text().count('disabled; waiting') == 2)
        process.terminate()
        assert process.wait(timeout=1) == 0
        assert 'Client logged out' not in server_log.read_text()
        assert 'Runtime: not running' in command('status')
        command('enable')
        # Hold a UDP endpoint open without answering. Then start the mock only
        # after the first full handshake timeout; success must be a retry.
        with udp() as silent:
            retry_port = silent.getsockname()[1]
            retry_client, retry_log = launch(retry_port)
            assert select.select([silent], [], [], 2)[0]
            silent.recvfrom(4096)
            time.sleep(7)
            assert 'State: authenticating' in command('status'), 'Status expired during receive'
            wait_for(lambda: 'State: waiting to retry' in command('status'), 10)
            status = command('status')
            assert 'Authentication attempts: 1' in status and 'Next retry:' in status
            assert 'Connection timed out' in status
        with (root / 'retry-server.log').open('w') as output:
            retry_server = subprocess.Popen([server_exe, str(retry_port)], stdout=output, stderr=subprocess.STDOUT)
        processes.append(retry_server)
        wait_for(lambda: 'Connected successfully' in retry_log.read_text(), 6)
        assert 'Authentication attempts: 2' in command('status')
        assert 'State: authenticated' in command('status')
        retry_client.kill()
        retry_client.wait()
        assert 'Runtime: not running' in command('status'), 'Dead PID reported authenticated'
        snapshot = state / 'status'
        rows = snapshot.read_text().splitlines()
        metadata = rows[1].split()
        metadata[0] = str(os.getpid())
        metadata[1] = str(int(time.time()) - 60)
        rows[1] = ' '.join(metadata)
        snapshot.write_text('\n'.join(rows) + '\n')
        status = command('status')
        assert 'Runtime: running' in status and 'State: unknown (stale status)' in status
        print('Passed: persistent controls, cancellation, pause without logout, live/stale/dead status, single instance, automatic recovery after timeout')
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait()
