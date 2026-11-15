"""Repeat real daemon lifecycle transitions; optionally sample Linux resources."""
import argparse
import socket
import subprocess
import tempfile
from pathlib import Path
from fault_recovery import Server, wait_for

parser = argparse.ArgumentParser()
parser.add_argument('client')
parser.add_argument('--cycles', type=int, default=100)
args = parser.parse_args()
assert args.cycles > 0
client = str(Path(args.client).resolve())
server = Server('stale')
process = None
samples = []
try:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        state = root / 'state'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        config = root / 'test.conf'
        config.write_text(f'''username=soak_user
password=soak_password
ip=127.0.0.1
mac=4c:44:5b:00:81:24
server_ip=127.0.0.1
server_port={server.port}
client_ip=127.0.0.1
client_port={port}
auto_identity=false
auth_interval=1
heartbeat_interval=1
''')
        with (root / 'client.log').open('w') as log:
            process = subprocess.Popen([client, '-c', str(config), '--state-dir', str(state)],
                                       stdout=log, stderr=subprocess.STDOUT)
            def command(name):
                assert process.poll() is None, (root / 'client.log').read_text()
                return subprocess.check_output([client, name, '--state-dir', str(state)],
                                               text=True, timeout=3)
            for index in range(args.cycles):
                command('enable')
                wait_for(lambda: 'State: authenticated' in command('status'))
                command('disable')
                wait_for(lambda: 'State: disabled' in command('status'), 1)
                proc = Path('/proc') / str(process.pid)
                if index >= 4 and (proc / 'fd').exists():
                    fields = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                    samples.append((len(list((proc / 'fd').iterdir())),
                                    int(fields['Threads']), int(fields['VmRSS'].split()[0])))
            if samples:
                fds, threads, rss = zip(*samples)
                assert max(fds) - min(fds) <= 3, f'FD growth: {samples}'
                assert max(threads) <= 2, f'Worker threads survived disable: {samples}'
                assert max(rss) - min(rss) < 16 * 1024, f'RSS growth >16 MiB: {samples}'
                print(f'Linux samples: fd={min(fds)}..{max(fds)}, threads={min(threads)}..{max(threads)}, RSS KiB={min(rss)}..{max(rss)}')
            process.terminate()
            process.wait(timeout=3)
            print(f'{args.cycles} authenticated/disabled cycles passed')
finally:
    if process and process.poll() is None:
        process.kill()
        process.wait()
    server.close()
