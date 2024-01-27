pub mod cookie;
pub mod htmx;
pub mod login;
pub mod session;

const SESSION_KEY_COOKIE_NAME: &str = "session-key";

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use axum::{async_trait, routing::get, Router};
    use maud::{html, Markup};
    use tokio::net::TcpListener;

    use crate::{
        cookie::PulledSession,
        login::login_router,
        session::{AuthSessionLayer, IdSource, InitSession},
    };

    use self::{htmx::base_html, session::IdContext};

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_on_web() {
        let id_source = TestIdSource::new();
        let init_session = TestInitSession;
        let auth_session = Arc::new(AuthSessionLayer::new(
            Duration::from_secs(u64::MAX),
            id_source,
            init_session,
        ));
        let login_router = login_router(Arc::clone(&auth_session));
        let router = Router::new()
            .route("/session", get(show_session))
            .with_state(auth_session)
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
            p { "Username:" }
            p { (session.id.username) }
        };
        base_html(body)
    }

    #[derive(Debug)]
    struct Id {
        username: String,
    }
    #[derive(Debug)]
    struct Session {
        id: Id,
    }

    /// Id Source with preset users for test
    #[derive(Debug)]
    struct TestIdSource {
        users: HashMap<String, String>,
    }
    impl TestIdSource {
        pub fn new() -> Self {
            let users = [("foo", "bar")]
                .into_iter()
                .map(|(u, p)| (u.to_owned(), p.to_owned()));
            let users = HashMap::from_iter(users);
            Self { users }
        }
    }
    #[async_trait]
    impl IdSource for TestIdSource {
        type Id = Id;
        async fn id(&self, cx: &IdContext<'_>) -> Option<Self::Id> {
            if self.users.get(cx.username)? != cx.password {
                return None;
            }
            Some(Id {
                username: cx.username.to_owned(),
            })
        }
    }

    /// Convert `Id` to `Session`
    #[derive(Debug)]
    struct TestInitSession;
    impl InitSession for TestInitSession {
        type Id = Id;
        type Session = Session;
        fn init_session(&self, id: Self::Id) -> Self::Session {
            Session { id }
        }
    }
}
