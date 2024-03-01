use std::sync::Arc;

use axum_client_ip::SecureClientIpSource;
use change_password::change_password_router;
use login::login_router;
use session::AuthSessionLayer;

pub mod change_password;
pub mod login;
pub mod password;
pub mod req;
pub mod session;

const SESSION_KEY_COOKIE_NAME: &str = "session-key";

pub fn auth_router<Session>(
    ip_source: SecureClientIpSource,
    auth_state: Arc<AuthSessionLayer<Session>>,
) -> axum::Router
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    axum::Router::new()
        .nest("/", login_router(ip_source.clone(), auth_state.clone()))
        .nest(
            "/",
            change_password_router(ip_source.clone(), auth_state.clone()),
        )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::SocketAddr, sync::Mutex, time::Duration};

    use axum::{async_trait, extract::FromRef, routing::get, Router};
    use htmx_util::base_html;
    use maud::{html, Markup};
    use tokio::net::TcpListener;

    use crate::{req::AuthSession, session::InitSession};

    use self::session::{AuthState, ChangePassword, ChangePasswordContext, IdContext};

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_on_web() {
        let users = Arc::new(Mutex::new(HashMap::new()));
        let init_session = TestInitSession::new(users.clone());
        let change_password = TestChangePassword::new(users);
        let auth_state = Arc::new(AuthSessionLayer::new(
            Duration::from_secs(u64::MAX),
            init_session,
            change_password,
        ));
        let ip_source = SecureClientIpSource::ConnectInfo;
        let auth_router = auth_router(ip_source.clone(), Arc::clone(&auth_state));

        let router = Router::new()
            .route("/session", get(show_session))
            .with_state(auth_state)
            .nest("/", auth_router)
            .layer(ip_source.into_extension());
        let listener = TcpListener::bind("127.0.0.1:6969")
            .await
            .expect("failed to bind");
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("failed to serve");
    }

    async fn show_session(AuthSession(session): AuthSession<Session>) -> Markup {
        let body = html! {
            h1 { "Session" }
            p {
                span { "Username: " }
                span { (session.id.username) }
            }
        };
        base_html(body)
    }

    struct State {
        auth: Arc<AuthSessionLayer<Session>>,
    }

    impl FromRef<State> for AuthState<Session> {
        fn from_ref(input: &State) -> Self {
            Arc::clone(&input.auth)
        }
    }

    #[derive(Debug)]
    struct Id {
        username: String,
    }
    #[derive(Debug)]
    struct Session {
        id: Id,
    }

    /// Create a `Session` based on the given user credential with preset users for test
    ///
    /// This can be a database handle in production
    #[derive(Debug)]
    struct TestInitSession {
        users: Arc<Mutex<HashMap<String, String>>>,
    }
    impl TestInitSession {
        pub fn new(users: Arc<Mutex<HashMap<String, String>>>) -> Self {
            {
                let mut u = users.lock().unwrap();
                let new_users = [("foo", "bar")]
                    .into_iter()
                    .map(|(u, p)| (u.to_owned(), p.to_owned()));
                u.extend(new_users);
            }
            Self { users }
        }
    }
    #[async_trait]
    impl InitSession for TestInitSession {
        type Session = Session;
        async fn init_session(&self, cx: &IdContext<'_>) -> Option<Self::Session> {
            let users = self.users.lock().unwrap();
            if users.get(cx.username)? != cx.password {
                return None;
            }
            let id = Id {
                username: cx.username.to_owned(),
            };
            Some(Session { id })
        }
    }

    /// Change password of a user
    ///
    /// This can be a database operation
    #[derive(Debug)]
    struct TestChangePassword {
        users: Arc<Mutex<HashMap<String, String>>>,
    }
    impl TestChangePassword {
        pub fn new(users: Arc<Mutex<HashMap<String, String>>>) -> Self {
            Self { users }
        }
    }
    #[async_trait]
    impl ChangePassword for TestChangePassword {
        async fn change_password(
            &self,
            username: &str,
            cx: &ChangePasswordContext<'_>,
        ) -> Result<(), &'static str> {
            let mut u = self.users.lock().unwrap();
            let Some(p) = u.get_mut(username) else {
                return Err("User not exists");
            };
            if p != cx.old_password {
                return Err("Wrong old password");
            }
            *p = cx.new_password.into();
            Ok(())
        }
    }
}
