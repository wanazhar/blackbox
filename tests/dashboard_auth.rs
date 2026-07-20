//! 1.5 H1: dashboard session cookie + bearer auth.

use blackbox::serve::{cookie_value, SESSION_COOKIE};
// Re-export tests live primarily in serve unit tests; this integration test
// locks the public cookie helper contract used by browsers.

use axum::http::{header, HeaderMap};

#[test]
fn cookie_parser_ignores_other_cookies() {
    let mut h = HeaderMap::new();
    h.insert(
        header::COOKIE,
        "a=1; blackbox_session=deadbeef; b=2".parse().unwrap(),
    );
    assert_eq!(cookie_value(&h, SESSION_COOKIE).as_deref(), Some("deadbeef"));
    assert!(cookie_value(&h, "missing").is_none());
}

#[test]
fn session_cookie_name_is_stable() {
    assert_eq!(SESSION_COOKIE, "blackbox_session");
}
