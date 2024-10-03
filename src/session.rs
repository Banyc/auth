use std::{net::IpAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use primitive::map::expiring_map::ExpiringHashMap;
use rand::distributions::{Alphanumeric, DistString};
use tokio::sync::{mpsc, oneshot};

const SESSION_KEY_LENGTH: usize = 64;

pub type AuthState<Session> = Arc<AuthSessionLayer<Session>>;
pub type Username = Arc<str>;

#[derive(Debug)]
pub struct AuthSession<Session> {
    pub username: Username,
    pub user_session: Arc<Session>,
}
impl<Session> Clone for AuthSession<Session> {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            user_session: self.user_session.clone(),
        }
    }
}

type SessionLayer<Session> = ExpiringHashMap<String, AuthSession<Session>>;

#[derive(Debug)]
pub struct AuthSessionLayerHandler<Session> {
    tx: tokio::sync::mpsc::Sender<AuthSessionLayerMessage<Session>>,
}
impl<Session> Clone for AuthSessionLayerHandler<Session> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}
impl<Session: Sync + Send + 'static> AuthSessionLayerHandler<Session> {
    pub fn new(mut layer: AuthSessionLayer<Session>) -> Self {
        let (tx, mut rx) = mpsc::channel(1);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    AuthSessionLayerMessage::Login { req, resp } => {
                        let username = req.1.username.clone();
                        let f = || (req.2)(username);
                        let res = layer.login(req.0, &req.1, f).await;
                        let _ = resp.send(res);
                    }
                    AuthSessionLayerMessage::ChangePassword { req, resp } => {
                        let res = layer.change_password(req.0, &req.1).await;
                        let _ = resp.send(res);
                    }
                    AuthSessionLayerMessage::Session { req, resp } => {
                        let res = layer.session(req.0, &req.1).await;
                        let _ = resp.send(res);
                    }
                }
            }
        });
        Self { tx }
    }

    pub async fn request(&self, msg: AuthSessionLayerMessage<Session>) {
        self.tx.send(msg).await.unwrap();
    }
}
pub enum AuthSessionLayerMessage<Session> {
    Login {
        #[allow(clippy::type_complexity)]
        req: (Option<IpAddr>, BasicCredential, fn(Arc<str>) -> Session),
        resp: oneshot::Sender<Result<String, LoginError>>,
    },
    ChangePassword {
        req: (Option<IpAddr>, PasswordChangeReq),
        resp: oneshot::Sender<Result<(), &'static str>>,
    },
    Session {
        req: (Option<IpAddr>, Arc<str>),
        resp: oneshot::Sender<Option<AuthSession<Session>>>,
    },
}

#[derive(Debug)]
struct ExpiringAttemptMap<K> {
    map: ExpiringHashMap<K, LoginAttempt>,
}
impl<K: Eq + core::hash::Hash + Clone> ExpiringAttemptMap<K> {
    pub fn new(duration: Duration) -> Self {
        Self {
            map: ExpiringHashMap::new(duration),
        }
    }
    pub fn fail(&mut self, key: &K) {
        if self.map.get_mut(key).is_none() {
            self.map.insert(key.clone(), LoginAttempt::new());
        }
        if let Some(attempts) = self.map.get_mut(key) {
            attempts.fail();
        }
    }
    pub fn is_banned(&mut self, key: &K) -> bool {
        if let Some(attempts) = self.map.get(key) {
            if attempts.banned() {
                return true;
            }
        }
        false
    }
}

/// Authentication layer
#[derive(Debug)]
pub struct AuthSessionLayer<Session> {
    session: SessionLayer<Session>,
    ip_attempts: ExpiringAttemptMap<IpAddr>,
    username_attempts: ExpiringAttemptMap<Arc<str>>,
    user_layer: Box<dyn UserLayer>,
}
impl<Session: Sync + Send + 'static> AuthSessionLayer<Session> {
    pub fn new(timeout: Duration, user_layer: Box<dyn UserLayer>) -> Self {
        Self {
            session: SessionLayer::new(timeout),
            ip_attempts: ExpiringAttemptMap::new(Duration::from_secs(60 * 60)),
            username_attempts: ExpiringAttemptMap::new(Duration::from_secs(60 * 60)),
            user_layer,
        }
    }
}
impl<Session: 'static> AuthSessionLayer<Session> {
    /// Initiate a session gated by authentication and return the session key
    pub async fn login(
        &mut self,
        ip_addr: Option<IpAddr>,
        credential: &BasicCredential,
        new_session: impl FnOnce() -> Session,
    ) -> Result<String, LoginError> {
        if self.username_attempts.is_banned(&credential.username) {
            return Err(LoginError::TooManyAttempts);
        }
        if let Some(ip_addr) = ip_addr {
            if self.ip_attempts.is_banned(&ip_addr) {
                return Err(LoginError::TooManyAttempts);
            }
        }
        if !self.user_layer.auth(credential).await {
            self.username_attempts.fail(&credential.username);
            if let Some(ip_addr) = ip_addr {
                self.ip_attempts.fail(&ip_addr);
            }
            return Err(LoginError::WrongCreds);
        }
        let user_session = new_session();
        let session_key = Alphanumeric.sample_string(&mut rand::thread_rng(), SESSION_KEY_LENGTH);
        if self.session.get(&session_key).is_some() {
            return Err(LoginError::SessionCollision);
        }
        self.session.insert(
            session_key.clone(),
            AuthSession {
                username: credential.username.clone(),
                user_session: Arc::new(user_session),
            },
        );
        Ok(session_key)
    }

    pub async fn session(
        &mut self,
        ip_addr: Option<IpAddr>,
        session_key: &str,
    ) -> Option<AuthSession<Session>> {
        if let Some(ip_addr) = ip_addr {
            if self.ip_attempts.is_banned(&ip_addr) {
                return None;
            }
        }
        let res = { self.session.get(session_key).cloned() };
        if res.is_none() {
            if let Some(ip_addr) = ip_addr {
                self.ip_attempts.fail(&ip_addr);
            }
        }
        res
    }

    pub async fn change_password(
        &mut self,
        ip_addr: Option<IpAddr>,
        args: &PasswordChangeReq,
    ) -> Result<(), &'static str> {
        let res = self.user_layer.change_password(args).await;
        if res.is_err() {
            self.username_attempts.fail(&args.credential.username);
            if let Some(ip_addr) = ip_addr {
                self.ip_attempts.fail(&ip_addr);
            }
        }
        res
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

#[async_trait]
pub trait UserLayer: std::fmt::Debug + Sync + Send + 'static {
    /// `true`: auth successful
    async fn auth(&mut self, cx: &BasicCredential) -> bool;
    async fn change_password(&mut self, args: &PasswordChangeReq) -> Result<(), &'static str>;
}
#[derive(Debug, Clone)]
pub struct BasicCredential {
    pub username: Arc<str>,
    pub password: Arc<str>,
}
#[derive(Debug, Clone)]
pub struct PasswordChangeReq {
    pub credential: BasicCredential,
    pub new_password: Arc<str>,
}
