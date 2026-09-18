#![forbid(unsafe_code)]

//! Authenticate by PAM: a username and password through a PAM conversation,
//! refusing where no PAM stack is reachable.
//!
//! Pluggable Authentication Modules are how a Unix host decides a login:
//! a service name picks a stack of modules, the modules ask for what they
//! need through a conversation, and the stack concludes. The first gate
//! reads the name and calls it a `username` claim, with the password riding
//! on `Presented::proof` under `password`. This gate is the application's
//! side: it answers the stack's prompts with the presented credential and
//! turns the stack's conclusion into a verdict — `PAM_SUCCESS` proves the
//! claim, `PAM_AUTH_ERR` and `PAM_USER_UNKNOWN` refuse it alike, and an
//! expired account or a stack that will not be asked again is refused with
//! PAM's name for it and whatever the stack said.
//!
//! **No PAM stack is reachable from this build.** Calling `libpam` takes
//! unsafe code and `unsafe_code = "forbid"` stands in every crate, so the
//! host facility is the [`Stack`] trait, and an authenticator that is given
//! no stack refuses every login with that reason, on every operating system
//! (ADR-0050, amendment 2026-09-16). [`InProcess`] is a stack that lives in
//! the process, and is what the tests prove the conversation against. The
//! binding is queued behind the owner's ruling on where unsafe may live.
//! The mechanism keeps its own name, `pam`, so an Acceptance can say which
//! verifier a Location uses.

pub mod conversation;
pub mod stack;

pub use conversation::{Conversation, Credential, Prompt};
pub use stack::{InProcess, Stack, UNREACHABLE, Unreachable, Verdict};

use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use xcore::{Mechanism, mechanism};

/// The proof name this verifier reads off a `Presented`.
pub const PROOF: &str = "password";

/// Verifies a `username` claim with a `password` proof through a PAM stack.
pub struct PamAuthenticator {
    service: String,
    stack: Box<dyn Stack>,
}

impl PamAuthenticator {
    /// Authenticates for `service` against the stack this build reaches,
    /// which is none: every login is refused with the reason until
    /// [`PamAuthenticator::with_stack`] gives it one.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            stack: Box::new(Unreachable),
        }
    }

    /// The stack to authenticate through.
    #[must_use]
    pub fn with_stack(mut self, stack: impl Stack + 'static) -> Self {
        self.stack = Box::new(stack);
        self
    }

    /// The PAM service this authenticates for.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

/// Whether a claim is one this verifier reads: a bare `username`, or one
/// the first gate already filed under `pam`.
fn reads(mechanism: &Mechanism) -> bool {
    let name = mechanism.name();
    name == "username" || name == "pam"
}

impl Authenticator for PamAuthenticator {
    fn mechanism(&self) -> Mechanism {
        mechanism::pam()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if !reads(&presented.mechanism) {
            return Err(AuthenticateError::new(format!(
                "'{}' is not a claim the PAM verifier reads: it takes a username",
                presented.mechanism.name()
            )));
        }
        let password = presented.proof(PROOF).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no '{PROOF}' proof was presented with the username '{}'",
                presented.value
            ))
        })?;
        if presented.value.is_empty() {
            return Err(AuthenticateError::new("the username presented is empty"));
        }
        let mut credential = Credential::new(&presented.value, password);
        let verdict = self
            .stack
            .authenticate(&self.service, &presented.value, &mut credential)?;
        match verdict {
            Verdict::Success => Ok(Verified::Proven),
            Verdict::AuthenticationError | Verdict::UserUnknown => Ok(Verified::Refused),
            other => Err(AuthenticateError::new(format!(
                "the PAM service '{}' concluded {}{}",
                self.service,
                other.name(),
                if credential.said().is_empty() {
                    String::new()
                } else {
                    format!(": {}", credential.said().join("; "))
                }
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticate::store::CredentialStore;
    use authenticate::{Acceptance, PartyRegistry, Refusal, authenticate};
    use xcore::{PartyId, Purpose};

    fn verifier() -> PamAuthenticator {
        let store = CredentialStore::from_entries(64, [("alice", "pencil"), ("old", "pencil")]);
        PamAuthenticator::new("xmip").with_stack(InProcess::new("xmip", store).with_expired("old"))
    }

    fn claim(username: &str, password: &str) -> Presented {
        Presented::passed(mechanism::username(), username).with_proof(PROOF, password)
    }

    #[test]
    fn a_real_login_is_refused_with_the_reason_on_every_operating_system() {
        let verifier = PamAuthenticator::new("login");
        let failure = verifier
            .verify(&claim("alice", "pencil"))
            .expect_err("refused");
        assert!(
            failure
                .message
                .starts_with("no PAM stack is reachable from this build"),
            "{}",
            failure.message
        );
        assert!(failure.message.contains("'login'"), "{}", failure.message);
        assert_eq!(verifier.service(), "login");
        assert_eq!(verifier.mechanism().name(), "pam");
    }

    #[test]
    fn through_the_in_process_stack_the_right_password_proves_the_username() {
        let verifier = verifier();
        assert_eq!(
            verifier
                .verify(&claim("alice", "pencil"))
                .expect("verified"),
            Verified::Proven
        );
        // A claim the first gate already filed under this mechanism reads too.
        let filed = Presented::passed(mechanism::pam(), "alice").with_proof(PROOF, "pencil");
        assert_eq!(verifier.verify(&filed).expect("verified"), Verified::Proven);
    }

    #[test]
    fn a_wrong_password_and_an_unknown_user_are_refused_alike() {
        let verifier = verifier();
        assert_eq!(
            verifier.verify(&claim("alice", "pen")).expect("verified"),
            Verified::Refused
        );
        assert_eq!(
            verifier
                .verify(&claim("mallory", "pencil"))
                .expect("verified"),
            Verified::Refused
        );
    }

    #[test]
    fn an_expired_account_is_refused_with_pams_name_and_what_the_stack_said() {
        let failure = verifier()
            .verify(&claim("old", "pencil"))
            .expect_err("refused");
        assert_eq!(
            failure.message,
            "the PAM service 'xmip' concluded PAM_ACCT_EXPIRED: the account 'old' has expired"
        );
    }

    #[test]
    fn a_missing_proof_and_another_mechanism_are_refused_by_name() {
        let bare = Presented::passed(mechanism::username(), "alice");
        let failure = verifier().verify(&bare).expect_err("refused");
        assert!(
            failure.message.contains("'password' proof"),
            "{}",
            failure.message
        );
        // A Basic credential is another verifier's proof, not this one's.
        let basic = Presented::passed(mechanism::username(), "alice")
            .with_proof("basic.credential", "YWxpY2U6cGVuY2ls");
        assert!(verifier().verify(&basic).is_err());

        let key = Presented::passed(mechanism::api_key(), "k-1").with_proof("api-key", "s");
        let failure = verifier().verify(&key).expect_err("refused");
        assert!(failure.message.contains("'api-key'"), "{}", failure.message);
    }

    struct Registry;

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, _purpose: Purpose, value: &str) -> Option<PartyId> {
            (mechanism == "pam" && value == "alice").then(|| PartyId::new(3))
        }
    }

    #[test]
    fn through_the_gate_the_refusal_carries_the_reason_to_the_operator() {
        let acceptance = Acceptance::closed().accepting(&mechanism::pam());
        let filed = Presented::passed(mechanism::pam(), "alice").with_proof(PROOF, "pencil");

        let bound = verifier();
        let identity = authenticate(&acceptance, &[&bound], &Registry, &filed).expect("accepted");
        assert_eq!(identity.party_id, Some(PartyId::new(3)));

        let unbound = PamAuthenticator::new("xmip");
        let refusal =
            authenticate(&acceptance, &[&unbound], &Registry, &filed).expect_err("refused");
        assert!(
            matches!(&refusal, Refusal::NotProven { detail, .. } if detail.contains(UNREACHABLE)),
            "{refusal}"
        );
    }
}
