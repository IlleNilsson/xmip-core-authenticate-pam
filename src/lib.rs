#![forbid(unsafe_code)]
//! Authenticate by pam: verifies the credential through the host's PAM stack, refusing where
//! there is none.
//!
//! Declared and not yet written: `architecture.toml` carries the maturity. When it
//! is, it implements `Authenticator` (ADR-0050).
