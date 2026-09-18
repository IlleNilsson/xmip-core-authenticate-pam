//! The PAM stack: the host facility, as a trait, with the two
//! implementations this build has.
//!
//! `pam_authenticate(3)` followed by `pam_acct_mgmt(3)` is a call into C,
//! and `unsafe_code = "forbid"` stands in every crate of the estate
//! (ADR-0050, amendment 2026-09-16). So the facility is a trait.
//! [`Unreachable`] is what a node gets unless it is given another: it
//! refuses every login, on every operating system, and says why.
//! [`InProcess`] is a stack that lives in the process — one module that
//! asks for a password and checks it against a credential store — which is
//! what the tests run against and what a binding will be measured against
//! when the owner rules on where unsafe may live.

use crate::conversation::{Conversation, Prompt};
use authenticate::AuthenticateError;
use authenticate::store::CredentialStore;

/// Why [`Unreachable`] refuses, word for word.
pub const UNREACHABLE: &str = "no PAM stack is reachable from this build";

/// What a stack concluded, by the return codes of `pam_authenticate(3)` and
/// `pam_acct_mgmt(3)` a login meets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// `PAM_SUCCESS`.
    Success,
    /// `PAM_AUTH_ERR`: the credential is wrong.
    AuthenticationError,
    /// `PAM_USER_UNKNOWN`: the stack knows no such user.
    UserUnknown,
    /// `PAM_ACCT_EXPIRED`: the credential is right and the account is over.
    AccountExpired,
    /// `PAM_MAXTRIES`: the stack will not be asked again for now.
    MaxTries,
    /// `PAM_CONV_ERR`: the stack asked and was not answered.
    ConversationError,
}

impl Verdict {
    /// PAM's name for the return code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Success => "PAM_SUCCESS",
            Self::AuthenticationError => "PAM_AUTH_ERR",
            Self::UserUnknown => "PAM_USER_UNKNOWN",
            Self::AccountExpired => "PAM_ACCT_EXPIRED",
            Self::MaxTries => "PAM_MAXTRIES",
            Self::ConversationError => "PAM_CONV_ERR",
        }
    }
}

/// The host's PAM facility.
pub trait Stack: Send + Sync {
    /// Authenticate `username` for `service` — the name of the file under
    /// `/etc/pam.d` — asking `conversation` for whatever the modules need.
    ///
    /// # Errors
    ///
    /// The stack could not be run at all, which is not a verdict on the
    /// credential.
    fn authenticate(
        &self,
        service: &str,
        username: &str,
        conversation: &mut dyn Conversation,
    ) -> Result<Verdict, AuthenticateError>;
}

/// The stack of a build that binds none: every login is refused with the
/// reason.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unreachable;

impl Stack for Unreachable {
    fn authenticate(
        &self,
        service: &str,
        _username: &str,
        _conversation: &mut dyn Conversation,
    ) -> Result<Verdict, AuthenticateError> {
        Err(AuthenticateError::new(format!(
            "{UNREACHABLE}: binding libpam takes unsafe code, which the estate forbids, so the \
             service '{service}' was not asked"
        )))
    }
}

/// A stack in the process: one module that asks for the password and checks
/// it against a credential store, and an account phase that knows which
/// accounts are over.
#[derive(Debug)]
pub struct InProcess {
    service: String,
    store: CredentialStore,
    expired: Vec<String>,
}

impl InProcess {
    /// A stack answering for `service` with the users `store` holds.
    #[must_use]
    pub fn new(service: impl Into<String>, store: CredentialStore) -> Self {
        Self {
            service: service.into(),
            store,
            expired: Vec::new(),
        }
    }

    /// Mark an account as expired: its password still checks, and the
    /// account phase refuses it.
    #[must_use]
    pub fn with_expired(mut self, username: impl Into<String>) -> Self {
        self.expired.push(username.into());
        self
    }
}

impl Stack for InProcess {
    fn authenticate(
        &self,
        service: &str,
        username: &str,
        conversation: &mut dyn Conversation,
    ) -> Result<Verdict, AuthenticateError> {
        if service != self.service {
            return Err(AuthenticateError::new(format!(
                "the PAM stack has no service '{service}': it answers for '{}'",
                self.service
            )));
        }
        let Some(password) = conversation.answer(&Prompt::EchoOff("Password: ".to_string())) else {
            return Ok(Verdict::ConversationError);
        };
        if !self.store.verify(username, &password) {
            return Ok(if self.store.contains(username) {
                Verdict::AuthenticationError
            } else {
                Verdict::UserUnknown
            });
        }
        if self.expired.iter().any(|name| name == username) {
            let _ = conversation.answer(&Prompt::Error(format!(
                "the account '{username}' has expired"
            )));
            return Ok(Verdict::AccountExpired);
        }
        Ok(Verdict::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Credential;

    fn stack() -> InProcess {
        let store = CredentialStore::from_entries(64, [("alice", "pencil"), ("old", "pencil")]);
        InProcess::new("xmip", store).with_expired("old")
    }

    fn verdict(stack: &dyn Stack, username: &str, password: &str) -> Verdict {
        let mut credential = Credential::new(username, password);
        stack
            .authenticate("xmip", username, &mut credential)
            .expect("the stack ran")
    }

    #[test]
    fn the_in_process_stack_asks_for_the_password_and_concludes_as_pam_does() {
        let stack = stack();
        assert_eq!(verdict(&stack, "alice", "pencil"), Verdict::Success);
        assert_eq!(
            verdict(&stack, "alice", "pen"),
            Verdict::AuthenticationError
        );
        assert_eq!(verdict(&stack, "mallory", "pencil"), Verdict::UserUnknown);
        assert_eq!(verdict(&stack, "old", "pencil"), Verdict::AccountExpired);
        assert_eq!(Verdict::AccountExpired.name(), "PAM_ACCT_EXPIRED");
    }

    #[test]
    fn a_conversation_that_does_not_answer_is_a_conversation_error() {
        struct Silent;
        impl Conversation for Silent {
            fn answer(&mut self, _prompt: &Prompt) -> Option<String> {
                None
            }
        }
        let concluded = stack()
            .authenticate("xmip", "alice", &mut Silent)
            .expect("the stack ran");
        assert_eq!(concluded, Verdict::ConversationError);
    }

    #[test]
    fn a_service_the_stack_does_not_have_is_an_error_and_not_a_verdict() {
        let mut credential = Credential::new("alice", "pencil");
        let failure = stack()
            .authenticate("sshd", "alice", &mut credential)
            .expect_err("no such service");
        assert!(failure.message.contains("'sshd'"), "{}", failure.message);
    }

    #[test]
    fn the_unreachable_stack_asks_nothing_and_says_why() {
        struct Asked(bool);
        impl Conversation for Asked {
            fn answer(&mut self, _prompt: &Prompt) -> Option<String> {
                self.0 = true;
                None
            }
        }
        let mut asked = Asked(false);
        let failure = Unreachable
            .authenticate("login", "alice", &mut asked)
            .expect_err("refused");
        assert!(
            failure.message.starts_with(UNREACHABLE),
            "{}",
            failure.message
        );
        assert!(!asked.0);
    }
}
