// Unit tests for UTF-8 safe truncation

/// Safely truncate a string to a maximum byte length at a valid UTF-8 character boundary
fn truncate_utf8_safe(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }

    // Find the last character boundary at or before max_bytes
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }

    &s[..boundary]
}

#[test]
fn test_truncate_utf8_safe_ascii() {
    let text = "Hello, World!";
    assert_eq!(truncate_utf8_safe(text, 5), "Hello");
    assert_eq!(truncate_utf8_safe(text, 100), text);
}

#[test]
fn test_truncate_utf8_safe_multibyte() {
    // Japanese characters (3 bytes each in UTF-8)
    let text = "こんにちは世界"; // "Hello World" in Japanese

    // Should truncate at character boundary, not mid-character
    let result = truncate_utf8_safe(text, 10);
    assert!(result.is_char_boundary(result.len()));
    assert!(result.len() <= 10);
}

#[test]
fn test_truncate_utf8_safe_emoji() {
    // Emoji (4 bytes each in UTF-8)
    let text = "Hello 🔥🚀💻 World";

    // Should never panic, even if limit falls in middle of emoji
    let result = truncate_utf8_safe(text, 8);
    assert!(result.is_char_boundary(result.len()));
    assert!(result.len() <= 8);
}

#[test]
fn test_truncate_utf8_safe_boundary_at_multibyte() {
    // Create text where byte limit would fall in middle of multi-byte char
    let text = "ABC日本語"; // "ABC" + Japanese (each Japanese char = 3 bytes)

    // Limit of 5 would fall in middle of first Japanese character (at byte 3+2=5)
    // Should truncate to "ABC" (3 bytes)
    let result = truncate_utf8_safe(text, 5);
    assert_eq!(result, "ABC");
    assert!(result.is_char_boundary(result.len()));
}

#[test]
fn test_truncate_utf8_safe_exact_boundary() {
    let text = "ABC日"; // "ABC" (3 bytes) + "日" (3 bytes) = 6 bytes total

    // Limit of 6 should return full string
    let result = truncate_utf8_safe(text, 6);
    assert_eq!(result, text);

    // Limit of 3 should return "ABC"
    let result = truncate_utf8_safe(text, 3);
    assert_eq!(result, "ABC");
}

#[test]
fn test_truncate_utf8_safe_empty() {
    let text = "";
    assert_eq!(truncate_utf8_safe(text, 10), "");
}

#[test]
fn test_truncate_utf8_safe_zero_limit() {
    let text = "Hello";
    assert_eq!(truncate_utf8_safe(text, 0), "");
}
