//! The PAM conversation: what a stack asks, and who answers.
//!
//! A PAM module does not take a password; it asks for one, through a
//! conversation function the application hands it, in one of four message
//! styles (`pam_conv(3)`). A headless node has nobody to show a prompt to,
//! so the application's side of the conversation is the credential that was
//! presented: a prompt with echo off is answered with the password, a
//! prompt with echo on with the username, and what the stack merely says is
//! kept, because it is often the only reason a refusal comes with.

use std::fmt;

/// One message from the stack, by PAM's four styles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Prompt {
    /// `PAM_PROMPT_ECHO_OFF`: a secret is asked for.
    EchoOff(String),
    /// `PAM_PROMPT_ECHO_ON`: something that may be shown is asked for.
    EchoOn(String),
    /// `PAM_ERROR_MSG`: the stack reports a problem and expects no answer.
    Error(String),
    /// `PAM_TEXT_INFO`: the stack says something and expects no answer.
    Info(String),
}

/// The application's side of the conversation.
pub trait Conversation {
    /// Answer one message. `None` where the message expects no answer, or
    /// where there is none to give, which ends the conversation.
    fn answer(&mut self, prompt: &Prompt) -> Option<String>;
}

/// A presented credential, answering for itself.
pub struct Credential<'a> {
    username: &'a str,
    password: &'a str,
    said: Vec<String>,
}

impl<'a> Credential<'a> {
    #[must_use]
    pub const fn new(username: &'a str, password: &'a str) -> Self {
        Self {
            username,
            password,
            said: Vec::new(),
        }
    }

    /// What the stack said along the way, errors and information alike, in
    /// the order it said them.
    #[must_use]
    pub fn said(&self) -> &[String] {
        &self.said
    }
}

impl fmt::Debug for Credential<'_> {
    /// The password is not printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("username", &self.username)
            .field("said", &self.said)
            .finish_non_exhaustive()
    }
}

impl Conversation for Credential<'_> {
    fn answer(&mut self, prompt: &Prompt) -> Option<String> {
        match prompt {
            Prompt::EchoOff(_) => Some(self.password.to_string()),
            Prompt::EchoOn(_) => Some(self.username.to_string()),
            Prompt::Error(text) | Prompt::Info(text) => {
                self.said.push(text.clone());
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_answers_a_secret_prompt_with_the_password_and_an_open_one_with_the_name() {
        let mut credential = Credential::new("alice", "pencil");
        let secret = credential.answer(&Prompt::EchoOff("Password: ".to_string()));
        assert_eq!(secret.as_deref(), Some("pencil"));
        let open = credential.answer(&Prompt::EchoOn("login: ".to_string()));
        assert_eq!(open.as_deref(), Some("alice"));
    }

    #[test]
    fn what_the_stack_says_is_kept_and_not_answered_and_the_password_is_not_printed() {
        let mut credential = Credential::new("alice", "pencil");
        assert_eq!(
            credential.answer(&Prompt::Info("Last login: Monday".to_string())),
            None
        );
        assert_eq!(
            credential.answer(&Prompt::Error("Account locked".to_string())),
            None
        );
        assert_eq!(credential.said(), ["Last login: Monday", "Account locked"]);
        let printed = format!("{credential:?}");
        assert!(printed.contains("alice") && !printed.contains("pencil"));
    }
}
