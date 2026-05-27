use std::{thread, time::Duration};

use sentinel::uuid7::uuid7;
use uuid::{Uuid, Variant, Version};

#[test]
fn uuid7_returns_uuid() {
    let result = uuid7();
    let _: Uuid = result;
}

#[test]
fn uuid7_version_is_7() {
    let result = uuid7();
    assert_eq!(result.get_version(), Some(Version::SortRand));
}

#[test]
fn uuid7_variant_is_rfc4122() {
    let result = uuid7();
    assert_eq!(result.get_variant(), Variant::RFC4122);
}

#[test]
fn uuid7_uniqueness() {
    let ids = (0..1000)
        .map(|_| uuid7())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn uuid7_time_ordering() {
    let a = uuid7();
    thread::sleep(Duration::from_millis(2));
    let b = uuid7();

    assert!(a.to_string() < b.to_string());
}

#[test]
fn uuid7_string_format() {
    let result = uuid7();
    let rendered = result.to_string();
    let parts = rendered.split('-').map(str::len).collect::<Vec<_>>();

    assert_eq!(parts, vec![8, 4, 4, 4, 12]);
}
