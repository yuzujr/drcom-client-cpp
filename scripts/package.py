#!/usr/bin/env python3
"""Install, archive, extract and test the exact payload distributed to users."""
import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    parser.add_argument('--config', default='Release')
    parser.add_argument('--tag', help='Optional release tag; must equal v + VERSION')
    args = parser.parse_args()
    version = (ROOT / 'VERSION').read_text().strip()
    if args.tag and args.tag != f'v{version}':
        parser.error(f'Tag {args.tag!r} does not match VERSION (v{version})')
    system = {'Linux': 'linux', 'Windows': 'windows', 'Darwin': 'macos'}[platform.system()]
    arch = {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(platform.machine().lower(), platform.machine().lower())
    name = f'drcom-client-{version}-{system}-{arch}'
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    suffix = '.zip' if os.name == 'nt' else '.tar.gz'
    extension = '.exe' if os.name == 'nt' else ''
    with tempfile.TemporaryDirectory(prefix='drcom-package-') as directory:
        work = Path(directory)
        stage = work / name
        run('cmake', '--install', args.build_dir.resolve(), '--config', args.config, '--prefix', stage)
        client = stage / 'bin' / f'drcom_client{extension}'
        server = stage / 'bin' / f'mock_drcom_server{extension}'
        for file in [client, server, stage / 'share/drcom-client-cpp/config/drcom_jlu.conf',
                     stage / 'share/drcom-client-cpp/config/drcom_test.conf']:
            if not file.is_file():
                raise RuntimeError(f'Installed package is missing {file.relative_to(stage)}')
        if os.name == 'nt' and not (stage / 'bin/windows-autostart.ps1').is_file():
            raise RuntimeError('Windows startup helper missing')
        if os.name == 'nt':
            archive = Path(shutil.make_archive(str(output / name), 'zip', work, name))
        else:
            archive = output / (name + suffix)
            with tarfile.open(archive, 'w:gz') as tar:
                tar.add(stage, arcname=name)
        extracted = work / 'extracted'
        shutil.unpack_archive(archive, extracted)
        payload = extracted / name
        client = payload / 'bin' / client.name
        server = payload / 'bin' / server.name
        # Execute from an empty CWD, with only the extracted install available.
        empty = work / 'empty'
        empty.mkdir()
        result = run(client, '--version', cwd=empty, capture_output=True, text=True)
        if result.stdout.strip() != f'v{version}':
            raise RuntimeError(f'Installed binary version mismatch: {result.stdout!r}')
        result = run(client, 'status', '--state-dir', empty / 'state', cwd=empty,
                     capture_output=True, text=True)
        if 'Runtime: unknown' not in result.stdout:
            raise RuntimeError(f'Unexpected clean runtime status: {result.stdout!r}')
        run(sys.executable, ROOT / 'tests/fault_recovery.py', client, cwd=empty)
        if os.name != 'nt':
            run(sys.executable, ROOT / 'tests/runtime_control.py', client, server, cwd=empty)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = output / (archive.name + '.sha256')
        checksum.write_text(f'{digest}  {archive.name}\n', encoding='ascii')
        if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum.read_text().split()[0]:
            raise RuntimeError('Archive checksum verification failed')
        print(f'Validated extracted package: {archive}\nSHA-256: {digest}')


if __name__ == '__main__':
    main()
