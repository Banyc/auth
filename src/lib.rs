use std::time::Duration;

use rand::distributions::{Alphanumeric, DistString};
use session::MutSessionLayer;
use tokio::sync::OwnedMutexGuard;

const SESSION_KEY_LENGTH: usize = 16;

/// Authentiction layer
#[derive(Debug)]
pub struct AuthSessionLayer<Session, IdSource> {
    session: MutSessionLayer<String, Session>,
    id_source: IdSource,
}
impl<Session: Sync + Send + 'static, IdSource> AuthSessionLayer<Session, IdSource> {
    pub fn new(timeout: Duration, id_source: IdSource) -> Self {
        Self {
            session: MutSessionLayer::new(timeout),
            id_source,
        }
    }
}
impl<Session, IS, Id> AuthSessionLayer<Session, IS>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    IS: IdSource<Id = Id>,
{
    /// Initiate a session gated by authentication
    pub async fn login(
        &mut self,
        id_context: &IdContext<'_>,
        init_session: impl FnOnce(Id) -> Session,
    ) -> Result<String, LoginError> {
        let id = self
            .id_source
            .id(id_context)
            .await
            .ok_or(LoginError::WrongCreds)?;
        let session = init_session(id);
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

pub trait IdSource {
    type Id;
    /// Return [`None`] if the authentication failed
    fn id(&self, cx: &IdContext<'_>) -> impl std::future::Future<Output = Option<Self::Id>> + Send;
}

#[derive(Debug)]
pub struct IdContext<'caller> {
    pub username: &'caller str,
    pub password: &'caller str,
}
