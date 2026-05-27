use uuid::Uuid;

/// Generate an RFC 9562 UUIDv7 value.
pub fn uuid7() -> Uuid {
    Uuid::now_v7()
}
