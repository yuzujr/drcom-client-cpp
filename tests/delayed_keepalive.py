"""Exercise real client/mock protocol through a UDP relay with 800 ms heartbeat latency."""
import heapq
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    return sock


with tempfile.TemporaryDirectory() as directory:
    front, upstream, reserved = udp(), udp(), udp()
    server_port = reserved.getsockname()[1]
    reserved.close()
    server_log = open(Path(directory) / 'server.log', 'w+')
    client_log = open(Path(directory) / 'client.log', 'w+')
    server = subprocess.Popen([sys.argv[2], str(server_port)], stdout=server_log, stderr=subprocess.STDOUT)
    client_reserved = udp()
    client_port = client_reserved.getsockname()[1]
    client_reserved.close()
    client = None
    try:
        time.sleep(0.3)
        config = Path(directory) / 'test.conf'
        config.write_text(f'''username=test_user
password=test_pass
ip=127.0.0.1
mac=4c:44:5b:00:81:24
server_ip=127.0.0.1
server_port={front.getsockname()[1]}
client_ip=127.0.0.1
client_port={client_port}
auto_identity=false
auto_reconnect=false
auth_interval=2
heartbeat_interval=2
debug=true
''')
        client = subprocess.Popen([sys.argv[1], '--state-dir', str(Path(directory) / 'state'), '-c', str(config)], stdout=client_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 18
        pending = []
        peer = None
        delayed = 0
        while time.monotonic() < deadline:
            if client.poll() is not None:
                raise RuntimeError('Client exited during delayed heartbeat test')
            readable, _, _ = select.select([front, upstream], [], [], 0.05)
            for sock in readable:
                data, address = sock.recvfrom(4096)
                if sock is front:
                    peer = address
                    upstream.sendto(data, ('127.0.0.1', server_port))
                else:
                    delay = 0.8 if data[0] == 0x07 else 0
                    delayed += bool(delay)
                    heapq.heappush(pending, (time.monotonic() + delay, data))
            while pending and pending[0][0] <= time.monotonic():
                _, data = heapq.heappop(pending)
                front.sendto(data, peer)
        client.send_signal(signal.SIGTERM)
        # Relay logout traffic as well so normal shutdown is checked.
        shutdown_deadline = time.monotonic() + 6
        while client.poll() is None and time.monotonic() < shutdown_deadline:
            readable, _, _ = select.select([front, upstream], [], [], 0.05)
            for sock in readable:
                data, address = sock.recvfrom(4096)
                if sock is front:
                    upstream.sendto(data, ('127.0.0.1', server_port))
                else:
                    front.sendto(data, peer)
        client_log.seek(0)
        output = client_log.read()
        if client.poll() != 0 or delayed < 6 or output.count('Connected successfully') != 1 or '[WARNING]' in output or '[WARN]' in output or '[ERROR]' in output:
            raise RuntimeError(f'Unexpected result: exit={client.poll()}, delayed={delayed}\n{output}')
        print(f'Passed: {delayed} keepalive replies delayed 800 ms; one login; clean shutdown')
    except Exception:
        client_log.seek(0)
        print(client_log.read())
        raise
    finally:
        for process in (client, server):
            if process is not None and process.poll() is None:
                process.kill()
            if process is not None:
                process.wait()
        front.close()
        upstream.close()
        server_log.close()
        client_log.close()
