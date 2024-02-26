use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::async_trait;
use rand::distributions::{Alphanumeric, DistString};
use session::MutSessionLayer;
use tokio::sync::OwnedMutexGuard;

use crate::expiring_hash_map::ExpiringHashMap;

const SESSION_KEY_LENGTH: usize = 16;

pub type AuthState<Session> = Arc<AuthSessionLayer<Session>>;

/// Authentication layer
#[derive(Debug)]
pub struct AuthSessionLayer<Session> {
    session: MutSessionLayer<String, Session>,
    init_session: Box<dyn InitSession<Session = Session>>,
    login_attempts: Mutex<ExpiringHashMap<IpAddr, LoginAttempt>>,
}
impl<Session: Sync + Send + 'static> AuthSessionLayer<Session> {
    pub fn new(timeout: Duration, init_session: impl InitSession<Session = Session>) -> Self {
        Self {
            session: MutSessionLayer::new(timeout),
            init_session: Box::new(init_session),
            login_attempts: Mutex::new(ExpiringHashMap::new(Duration::from_secs(60 * 60))),
        }
    }
}
impl<Session> AuthSessionLayer<Session>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    fn fail(&self, ip_addr: IpAddr) {
        let mut login_attempts = self.login_attempts.lock().unwrap();
        if login_attempts.get_mut(&ip_addr).is_none() {
            login_attempts.insert(ip_addr, LoginAttempt::new());
        }
        let attempts = login_attempts.get_mut(&ip_addr).unwrap();
        attempts.fail();
    }

    /// Initiate a session gated by authentication and return the session key
    pub async fn login(
        &self,
        ip_addr: IpAddr,
        id_context: &IdContext<'_>,
    ) -> Result<String, LoginError> {
        {
            let mut login_attempts = self.login_attempts.lock().unwrap();
            if let Some(attempts) = login_attempts.get(&ip_addr) {
                if attempts.banned() {
                    return Err(LoginError::TooManyAttempts);
                }
            }
        }
        let session = self
            .init_session
            .init_session(id_context)
            .await
            .ok_or_else(|| {
                self.fail(ip_addr);
                LoginError::WrongCreds
            })?;
        let session_key = Alphanumeric.sample_string(&mut rand::thread_rng(), SESSION_KEY_LENGTH);
        self.session
            .insert(session_key.clone(), session)
            .map_err(|_| LoginError::SessionCollision)?;
        Ok(session_key)
    }

    pub async fn get_mut(&self, session_key: &str) -> Option<OwnedMutexGuard<Session>> {
        self.session.get_mut(session_key).await
    }
}

const BAN_ATTEMPTS: usize = 16;
#[derive(Debug, Clone)]
struct LoginAttempt {
    failed_times: usize,
}
impl LoginAttempt {
    pub fn new() -> Self {
        Self { failed_times: 0 }
    }

    pub fn fail(&mut self) {
        self.failed_times = (self.failed_times + 1).min(BAN_ATTEMPTS);
    }

    pub fn banned(&self) -> bool {
        BAN_ATTEMPTS <= self.failed_times
    }
}
impl Default for LoginAttempt {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LoginError {
    #[error("Wrong password or username")]
    WrongCreds,
    /// Rarely happens
    #[error("Session collision")]
    SessionCollision,
    #[error("Too many attempts")]
    TooManyAttempts,
}

#[async_trait]
pub trait InitSession: std::fmt::Debug + Sync + Send + 'static {
    type Session;
    // Generate a session based on a user ID
    async fn init_session(&self, cx: &IdContext<'_>) -> Option<Self::Session>;
}

#[derive(Debug)]
pub struct IdContext<'caller> {
    pub username: &'caller str,
    pub password: &'caller str,
}
