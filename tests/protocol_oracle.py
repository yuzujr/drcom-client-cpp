"""Independent byte expectations using Python hashlib/struct; no production codec imports.

These freeze this client's existing wire profile, not a claim of complete server conformance.
"""
import hashlib
import random
import struct
import subprocess
import sys


def digest(data):
    return hashlib.md5(data).digest()


def folded(data, width, initial, multiplier):
    words = [int.from_bytes(data[i:i + width], 'little') for i in range(0, len(data), width)]
    for word in words:
        initial ^= word
    return struct.pack('<I', (initial * multiplier) & 0xffffffff)


def login(password):
    packet = bytearray(334 + (len(password) - 1) // 4 * 4)
    packet[:4] = bytes([3, 1, 0, 29])
    md5a = digest(b'\x03\x01\x01\x02\x03\x04' + password)
    packet[4:20] = md5a
    packet[20:29] = b'test_user'
    packet[58:64] = bytes(a ^ b for a, b in zip(bytes.fromhex('001122aabbcc'), md5a))
    packet[64:80] = digest(b'\x01' + password + b'\x01\x02\x03\x04' + bytes(4))
    packet[80:85] = bytes([1, 10, 20, 30, 40])
    packet[97:105] = digest(packet[:97] + bytes.fromhex('1400070b'))[:8]
    packet[105] = 1
    packet[110:119] = b'test-host'
    packet[142:150] = bytes(range(1, 9))
    packet[181:192] = bytes.fromhex('014472434f4d00cf076800')
    packet[192:199] = b'test-os'
    return bytes(packet)


def expected_packets():
    expected = {f'challenge_{name}': bytes([1, subtype, 0x12, 0x34, 0x68]) + bytes(15)
                for name, subtype in [('login', 2), ('logout', 3)]}
    expected.update({f'login_{size}': login(b'p' * size) for size in (1, 4, 5, 16, 17, 64)})
    md5a = digest(b'\x03\x01\x01\x02\x03\x04' + b'p' * 64)
    logout = bytearray(80)
    logout[:4] = bytes([6, 1, 0, 29])
    logout[4:20] = md5a
    logout[20:29] = b'test_user'
    logout[58:64] = bytes(a ^ b for a, b in zip(bytes.fromhex('001122aabbcc'), md5a))
    logout[64:68] = bytes([5, 6, 7, 8])
    expected['logout'] = bytes(logout)
    expected['auth'] = b'\xff' + md5a + bytes(3) + bytes(range(0x20, 0x30)) + bytes.fromhex('7856')
    for count in (0, 21, 255, 256):
        version = bytes.fromhex('0f27' if count == 0 else 'db02' if count == 21 else 'dc02')
        prefix = bytes([7, count & 255, 40, 0, 11, 1]) + version + bytes.fromhex('55667788') + bytes(4) + bytes.fromhex('11121314')
        expected[f'heartbeat_{count}'] = prefix + folded(prefix, 2, 0, 711) + bytes([10, 20, 30, 40]) + bytes(12)
    return expected


def compare(actual, expected, label):
    if actual != expected:
        mismatch = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]), min(len(actual), len(expected)))
        raise AssertionError(f'{label}: first difference at byte {mismatch}; lengths {len(actual)}/{len(expected)}')


def main():
    executable = sys.argv[1]
    result = subprocess.run([executable], check=True, capture_output=True, text=True)
    actual = dict(line.split(' ', 1) for line in result.stdout.splitlines())
    expected = expected_packets()
    assert actual.keys() == expected.keys(), 'Missing protocol vector'
    for name, value in expected.items():
        compare(bytes.fromhex(actual[name]), value, name)
    randomizer = random.Random(0xD2C0)
    inputs = [b'', b'a', b'abc', b'message digest', b'abcdefghijklmnopqrstuvwxyz']
    inputs += [randomizer.randbytes(size) for size in (1, 3, 4, 5, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 4096)]
    result = subprocess.run([executable, 'crypto'], input=''.join(data.hex() + '\n' for data in inputs),
                            check=True, capture_output=True, text=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(inputs) * 4
    for index, data in enumerate(inputs):
        values = [digest(data), folded(data, 4, 1234, 1968) + bytes(4),
                  folded(data, 2, 0, 711) + bytes(4), bytes(((b << 3) | (b >> 5)) & 255 for b in data)]
        for line, value in zip(lines[index * 4:index * 4 + 4], values):
            label, hex_value = line.split(' ', 1)
            compare(bytes.fromhex(hex_value), value, f'{label}, length={len(data)}')
    print(f'Passed: {len(expected)} wire vectors and {len(inputs)} independent crypto cases')


if __name__ == '__main__':
    main()
