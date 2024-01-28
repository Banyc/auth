use std::{sync::Arc, time::Duration};

use axum::async_trait;
use rand::distributions::{Alphanumeric, DistString};
use session::MutSessionLayer;
use tokio::sync::OwnedMutexGuard;

const SESSION_KEY_LENGTH: usize = 16;

pub type AuthState<Session> = Arc<AuthSessionLayer<Session>>;

/// Authentication layer
#[derive(Debug)]
pub struct AuthSessionLayer<Session> {
    session: MutSessionLayer<String, Session>,
    init_session: Box<dyn InitSession<Session = Session>>,
}
impl<Session: Sync + Send + 'static> AuthSessionLayer<Session> {
    pub fn new(timeout: Duration, init_session: impl InitSession<Session = Session>) -> Self {
        Self {
            session: MutSessionLayer::new(timeout),
            init_session: Box::new(init_session),
        }
    }
}
impl<Session> AuthSessionLayer<Session>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    /// Initiate a session gated by authentication and return the session key
    pub async fn login(&self, id_context: &IdContext<'_>) -> Result<String, LoginError> {
        let session = self
            .init_session
            .init_session(id_context)
            .await
            .ok_or(LoginError::WrongCreds)?;
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

#[derive(Debug, Clone, thiserror::Error)]
pub enum LoginError {
    #[error("Wrong password or username")]
    WrongCreds,
    /// Rarely happens
    #[error("Session collision")]
    SessionCollision,
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
