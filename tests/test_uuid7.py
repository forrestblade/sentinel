"""Tests for UUIDv7 generation."""

import time
import uuid

from sentinel.uuid7 import uuid7


def test_uuid7_returns_uuid():
    result = uuid7()
    assert isinstance(result, uuid.UUID)


def test_uuid7_version_is_7():
    result = uuid7()
    assert result.version == 7


def test_uuid7_variant():
    result = uuid7()
    # RFC 4122 variant (variant bits = 10)
    assert result.variant == uuid.RFC_4122


def test_uuid7_uniqueness():
    ids = {uuid7() for _ in range(1000)}
    assert len(ids) == 1000


def test_uuid7_time_ordering():
    a = uuid7()
    time.sleep(0.002)
    b = uuid7()
    # UUIDv7 sorts chronologically by string comparison
    assert str(a) < str(b)


def test_uuid7_string_format():
    result = uuid7()
    s = str(result)
    # Standard UUID format: 8-4-4-4-12
    parts = s.split("-")
    assert len(parts) == 5
    assert [len(p) for p in parts] == [8, 4, 4, 4, 12]
