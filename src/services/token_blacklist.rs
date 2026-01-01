//! Token blacklist service for server-side JWT invalidation.
//!
//! This module provides an in-memory token blacklist that stores invalidated
//! JWT tokens until they expire naturally. This allows for server-side logout
//! functionality without requiring database storage.

use dashmap::DashMap;
use log::{debug, info};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Represents a blacklisted token entry with its expiration time.
#[derive(Debug, Clone)]
struct BlacklistEntry {
    /// When this token expires and can be removed from the blacklist
    expires_at: Instant,
}

/// Thread-safe token blacklist using DashMap for concurrent access.
///
/// Tokens are stored with their expiration time and automatically cleaned up
/// periodically to prevent memory growth.
#[derive(Clone)]
pub struct TokenBlacklist {
    /// Map of token hash -> expiration entry
    /// We store a hash of the token rather than the token itself for security
    tokens: Arc<DashMap<String, BlacklistEntry>>,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl TokenBlacklist {
    /// Create a new empty token blacklist.
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Add a token to the blacklist.
    ///
    /// # Arguments
    /// * `token` - The JWT token to blacklist
    /// * `exp` - Token expiration timestamp (Unix epoch seconds)
    pub async fn blacklist_token(&self, token: &str, exp: usize) {
        // Calculate how long until the token expires
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Only add if the token hasn't already expired
        if exp > now_secs {
            let ttl = Duration::from_secs((exp - now_secs) as u64);
            let expires_at = Instant::now() + ttl;

            // Hash the token for storage (don't store the actual token)
            let token_hash = Self::hash_token(token);

            self.tokens.insert(token_hash, BlacklistEntry { expires_at });
            debug!("Token blacklisted, will expire in {:?}", ttl);
        }

        // Periodically cleanup expired tokens
        self.maybe_cleanup().await;
    }

    /// Check if a token is blacklisted.
    ///
    /// Returns `true` if the token is blacklisted (and should be rejected).
    pub fn is_blacklisted(&self, token: &str) -> bool {
        let token_hash = Self::hash_token(token);

        if let Some(entry) = self.tokens.get(&token_hash) {
            // Check if the entry has expired
            if entry.expires_at > Instant::now() {
                return true;
            }
            // Entry has expired, remove it
            drop(entry); // Release the read lock before removing
            self.tokens.remove(&token_hash);
        }

        false
    }

    /// Hash a token for secure storage.
    fn hash_token(token: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Clean up expired entries if enough time has passed since last cleanup.
    async fn maybe_cleanup(&self) {
        const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

        let should_cleanup = {
            let last = self.last_cleanup.read().await;
            last.elapsed() >= CLEANUP_INTERVAL
        };

        if should_cleanup {
            let mut last = self.last_cleanup.write().await;
            // Double-check after acquiring write lock
            if last.elapsed() >= CLEANUP_INTERVAL {
                self.cleanup();
                *last = Instant::now();
            }
        }
    }

    /// Remove all expired entries from the blacklist.
    fn cleanup(&self) {
        let now = Instant::now();
        let before_count = self.tokens.len();

        self.tokens.retain(|_, entry| entry.expires_at > now);

        let removed = before_count - self.tokens.len();
        if removed > 0 {
            info!(
                "Token blacklist cleanup: removed {} expired entries, {} remaining",
                removed,
                self.tokens.len()
            );
        }
    }

    /// Get the current number of blacklisted tokens.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if the blacklist is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Default for TokenBlacklist {
    fn default() -> Self {
        Self::new()
    }
}

