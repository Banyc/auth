use std::time::Duration;

use axum::async_trait;
use rand::distributions::{Alphanumeric, DistString};
use session::MutSessionLayer;
use tokio::sync::OwnedMutexGuard;

const SESSION_KEY_LENGTH: usize = 16;

/// Authentication layer
#[derive(Debug)]
pub struct AuthSessionLayer<Session, Id> {
    session: MutSessionLayer<String, Session>,
    id_source: Box<dyn IdSource<Id = Id>>,
    init_session: Box<dyn InitSession<Id = Id, Session = Session>>,
}
impl<Session: Sync + Send + 'static, Id> AuthSessionLayer<Session, Id> {
    pub fn new(
        timeout: Duration,
        id_source: impl IdSource<Id = Id>,
        init_session: impl InitSession<Id = Id, Session = Session>,
    ) -> Self {
        Self {
            session: MutSessionLayer::new(timeout),
            id_source: Box::new(id_source),
            init_session: Box::new(init_session),
        }
    }
}
impl<Session, Id> AuthSessionLayer<Session, Id>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    Id: std::fmt::Debug + Sync + Send + 'static,
{
    /// Initiate a session gated by authentication and return the session key
    pub async fn login(&self, id_context: &IdContext<'_>) -> Result<String, LoginError> {
        let id = self
            .id_source
            .id(id_context)
            .await
            .ok_or(LoginError::WrongCreds)?;
        let session = self.init_session.init_session(id);
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
pub trait IdSource: std::fmt::Debug + Sync + Send + 'static {
    type Id;
    /// Return [`None`] if the authentication failed
    // fn id(&self, cx: &IdContext<'_>) -> impl std::future::Future<Output = Option<Self::Id>> + Send;
    async fn id(&self, cx: &IdContext<'_>) -> Option<Self::Id>;
}

pub trait InitSession: std::fmt::Debug + Sync + Send + 'static {
    type Id;
    type Session;
    // Generate a session based on a user ID
    fn init_session(&self, id: Self::Id) -> Self::Session;
}

#[derive(Debug)]
pub struct IdContext<'caller> {
    pub username: &'caller str,
    pub password: &'caller str,
}
