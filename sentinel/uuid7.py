"""UUIDv7 generation per RFC 9562."""

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    """Generate a UUIDv7 with millisecond timestamp precision."""
    timestamp_ms = int(time.time() * 1000)
    # 48-bit timestamp
    ts_bytes = timestamp_ms.to_bytes(6, byteorder="big")
    # 10 bytes of randomness
    rand_bytes = os.urandom(10)
    # Assemble: 6 bytes timestamp + 2 bytes (version 7 + rand) + 8 bytes (variant + rand)
    raw = bytearray(16)
    raw[0:6] = ts_bytes
    raw[6:8] = rand_bytes[0:2]
    raw[8:16] = rand_bytes[2:10]
    # Set version 7 (bits 48-51)
    raw[6] = (raw[6] & 0x0F) | 0x70
    # Set variant 10 (bits 64-65)
    raw[8] = (raw[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(raw))
