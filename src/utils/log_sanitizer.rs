//! Log sanitization utilities for masking sensitive data.
//!
//! This module provides functions to mask sensitive information like emails
//! and usernames before logging, preventing accidental exposure of PII.

/// Mask an email address for safe logging.
///
/// Shows only the first 3 characters (or fewer if the local part is shorter)
/// followed by asterisks and the domain.
///
/// # Examples
/// ```ignore
/// assert_eq!(mask_email("user@example.com"), "use***@example.com");
/// assert_eq!(mask_email("ab@test.org"), "ab***@test.org");
/// ```
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local_part = &email[..at_pos];
        let domain = &email[at_pos..];

        let visible_chars = local_part.len().min(3);
        let masked_local = format!("{}***", &local_part[..visible_chars]);

        format!("{}{}", masked_local, domain)
    } else {
        // Not a valid email format, just mask most of it
        let visible_chars = email.len().min(3);
        format!("{}***", &email[..visible_chars])
    }
}

/// Mask a username for safe logging.
///
/// Shows only the first 3 characters followed by asterisks.
///
/// # Examples
/// ```ignore
/// assert_eq!(mask_username("johndoe"), "joh***");
/// assert_eq!(mask_username("ab"), "ab***");
/// ```
pub fn mask_username(username: &str) -> String {
    let visible_chars = username.len().min(3);
    format!("{}***", &username[..visible_chars])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_email_normal() {
        assert_eq!(mask_email("user@example.com"), "use***@example.com");
        assert_eq!(mask_email("johndoe@test.org"), "joh***@test.org");
    }

    #[test]
    fn test_mask_email_short_local_part() {
        assert_eq!(mask_email("ab@test.org"), "ab***@test.org");
        assert_eq!(mask_email("a@test.org"), "a***@test.org");
    }

    #[test]
    fn test_mask_email_invalid() {
        assert_eq!(mask_email("notanemail"), "not***");
    }

    #[test]
    fn test_mask_username() {
        assert_eq!(mask_username("johndoe"), "joh***");
        assert_eq!(mask_username("ab"), "ab***");
        assert_eq!(mask_username("a"), "a***");
    }
}

