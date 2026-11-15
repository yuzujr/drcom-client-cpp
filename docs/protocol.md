# Protocol verification

The codec in `src/protocol.cpp` preserves the existing client's wire profile.
Its inputs include the nonce, timestamp, counter and session values, so its
output can be tested without sockets, sleeping or global configuration.

`tests/protocol_oracle.py` calculates expectations with Python's `hashlib`,
integer operations and `struct`; it does not call production crypto helpers.
It compares complete packets, including padding, for both challenges, login
password lengths 1/4/5/16/17/64, logout, authentication keepalive and heartbeat
counters 0/21/255/256. Crypto inputs include block/padding boundaries and
unaligned input. Checksum/CRC results wider than 32 bits are zero-extended.

The mock rejects structurally invalid login packets. It is a flow simulator;
it does not validate real credentials or independently certify protocol
compatibility. The Python oracle checks the existing format, not the behavior
of every DRCOM server.

The login tail from offset 246 remains zero-filled, matching the implementation
before codec extraction. Filling it with guessed fields could break working
installations. Changing it, challenge matching rules, heartbeat matching rules,
or accepted response variants requires additional evidence: an independently
reviewed protocol implementation or a successful exchange with a compatible
campus server. No real campus exchange was available for this change.

When adding a captured fixture, use a dedicated test account and record the
server/client variant, capture conditions and expected behavior. Packet bytes
can contain usernames, MAC/IP addresses and password-derived data; removing
only plaintext passwords does not make a capture suitable for publication.
Use synthetic credentials and reproducible synthetic fixtures for the public
repository. Keep raw captures outside version control.
