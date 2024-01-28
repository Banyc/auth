pub mod cookie;
pub mod login;
pub mod password;
pub mod session;

const SESSION_KEY_COOKIE_NAME: &str = "session-key";

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use axum::{async_trait, extract::FromRef, routing::get, Router};
    use htmx_util::base_html;
    use maud::{html, Markup};
    use tokio::net::TcpListener;

    use crate::{
        cookie::PulledSession,
        login::login_router,
        session::{AuthSessionLayer, InitSession},
    };

    use self::session::{AuthState, IdContext};

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_on_web() {
        let init_session = TestInitSession::new();
        let auth_state = Arc::new(AuthSessionLayer::new(
            Duration::from_secs(u64::MAX),
            init_session,
        ));
        let login_router = login_router(Arc::clone(&auth_state));

        let router = Router::new()
            .route("/session", get(show_session))
            .with_state(auth_state)
            .nest("/", login_router);
        let listener = TcpListener::bind("127.0.0.1:6969")
            .await
            .expect("failed to bind");
        axum::serve(listener, router)
            .await
            .expect("failed to serve");
    }

    async fn show_session(PulledSession(session): PulledSession<Session>) -> Markup {
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
        users: HashMap<String, String>,
    }
    impl TestInitSession {
        pub fn new() -> Self {
            let users = [("foo", "bar")]
                .into_iter()
                .map(|(u, p)| (u.to_owned(), p.to_owned()));
            let users = HashMap::from_iter(users);
            Self { users }
        }
    }
    #[async_trait]
    impl InitSession for TestInitSession {
        type Session = Session;
        async fn init_session(&self, cx: &IdContext<'_>) -> Option<Self::Session> {
            if self.users.get(cx.username)? != cx.password {
                return None;
            }
            let id = Id {
                username: cx.username.to_owned(),
            };
            Some(Session { id })
        }
    }
}
