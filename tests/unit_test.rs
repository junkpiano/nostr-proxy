use nostr_proxy::truncate_utf8_safe;

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

#[test]
fn test_is_allowed_origin_production() {
    assert!(nostr_proxy::is_allowed_origin("https://nox.garden"));
    assert!(!nostr_proxy::is_allowed_origin("http://nox.garden"));
    assert!(!nostr_proxy::is_allowed_origin("https://www.nox.garden"));
    assert!(!nostr_proxy::is_allowed_origin(
        "https://nox.garden.evil.com"
    ));
    assert!(!nostr_proxy::is_allowed_origin("https://evilnox.garden"));
}

#[test]
fn test_is_allowed_origin_netlify_previews() {
    // The nox web build gets a Netlify deploy preview per pull request, so
    // link cards can be checked before a change is merged rather than after.
    assert!(nostr_proxy::is_allowed_origin(
        "https://nox-preview.netlify.app"
    ));
    assert!(nostr_proxy::is_allowed_origin(
        "https://deploy-preview-53--nox-preview.netlify.app"
    ));
    assert!(nostr_proxy::is_allowed_origin(
        "https://some-branch--nox-preview.netlify.app"
    ));

    // Netlify reads `<alias>--<site>` as an alias of that site, so the whole
    // `--nox-preview.netlify.app` namespace belongs to this site and a name
    // carrying `--` could never be routed to anyone else. Everything outside
    // it is a stranger's site.
    assert!(!nostr_proxy::is_allowed_origin(
        "https://someone-else.netlify.app"
    ));
    assert!(!nostr_proxy::is_allowed_origin(
        "https://nox-preview.netlify.app.evil.com"
    ));
    assert!(!nostr_proxy::is_allowed_origin(
        "https://evil-nox-preview.netlify.app"
    ));
    assert!(!nostr_proxy::is_allowed_origin(
        "https://x--nox-preview.netlify.app.evil.com"
    ));

    // Previews are served over TLS; there is no reason to accept anything
    // else.
    assert!(!nostr_proxy::is_allowed_origin(
        "http://nox-preview.netlify.app"
    ));
}

#[test]
fn test_is_allowed_origin_localhost() {
    assert!(nostr_proxy::is_allowed_origin("http://localhost:3000"));
    assert!(nostr_proxy::is_allowed_origin("http://localhost:8787"));
    assert!(nostr_proxy::is_allowed_origin("https://localhost"));
    assert!(nostr_proxy::is_allowed_origin("http://127.0.0.1:5173"));
    assert!(nostr_proxy::is_allowed_origin("http://[::1]:3000"));
    assert!(!nostr_proxy::is_allowed_origin("http://localhost.evil.com"));
}

#[test]
fn test_is_allowed_origin_garbage() {
    assert!(!nostr_proxy::is_allowed_origin(""));
    assert!(!nostr_proxy::is_allowed_origin("null"));
    assert!(!nostr_proxy::is_allowed_origin("https://example.com"));
    assert!(!nostr_proxy::is_allowed_origin("file:///etc/passwd"));
}
