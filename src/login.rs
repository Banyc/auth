use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Form,
};
use maud::{html, Markup, DOCTYPE};
use serde::Deserialize;

use crate::session::{AuthSessionLayer, IdContext, LoginError};

const ELEMENT_ID: &str = "login-form";
const SUBMIT_PATH: &str = "/login-summit";
const SUBMIT_INDICATOR_ID: &str = "login-submit-indicator";

type AuthState<Session, Id> = Arc<AuthSessionLayer<Session, Id>>;

pub fn login_router<Session, Id>(auth_session: Arc<AuthSessionLayer<Session, Id>>) -> axum::Router
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    Id: std::fmt::Debug + Sync + Send + 'static,
{
    axum::Router::new()
        .route("/login", get(login_page))
        .route(SUBMIT_PATH, post(login_submit))
        .with_state(auth_session)
}

/// Show the login page
async fn login_page() -> Markup {
    let form = login_form("");
    html! {
        (DOCTYPE)
        head {
            script src="https://unpkg.com/htmx.org@1.9.10"
                integrity="sha384-D1Kt99CQMDuVetoL1lrYwg5t+9QdHe7NLX/SoJYkXDFfX37iInKRy5xLSi8nO7UC"
                crossorigin="anonymous" {}
        }
        body {
            (form)
        }
    }
}

fn login_form(err_msg: &str) -> Markup {
    html! {
        div id=(ELEMENT_ID) {
            form {
                h1 { "Login" }
                input type="text" name="username" placeholder="username" {}
                br {}
                input type="password" name="password" placeholder="password" {}
                br {}
                button hx-target=(referred_id(ELEMENT_ID))
                    hx-trigger="click"
                    hx-post=(SUBMIT_PATH)
                    hx-indicator=(referred_id(SUBMIT_INDICATOR_ID))
                    { "Submit" }
            }
            br {}
            (err_msg)
            div id=(SUBMIT_INDICATOR_ID) class="htmx-indicator" {
                br {}
                img src="http://samherbert.net/svg-loaders/svg-loaders/oval.svg" {}
            }
        }
    }
}

#[derive(Deserialize)]
struct LoginForm {
    pub username: String,
    pub password: String,
}
async fn login_submit<Session, Id>(
    State(auth_session): State<AuthState<Session, Id>>,
    Form(form): Form<LoginForm>,
) -> (HeaderMap, Markup)
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    Id: std::fmt::Debug + Sync + Send + 'static,
{
    let cx = IdContext {
        username: &form.username,
        password: &form.password,
    };
    let session_key = match auth_session.login(&cx).await {
        Ok(x) => x,
        Err(e) => {
            let markup = match e {
                LoginError::SessionCollision => {
                    login_form("Too many active users. Try again later.")
                }
                LoginError::WrongCreds => login_form("Wrong!"),
            };
            return (HeaderMap::new(), markup);
        }
    };
    let markup = html! {
        p { "You have logged in successfully!" }
    };
    let mut header = HeaderMap::new();
    header.insert(
        "Set-Cookie",
        format!("session-key={session_key}; SameSite=None; Secure")
            .parse()
            .unwrap(),
    );
    (header, markup)
}

fn referred_id(id: &str) -> String {
    format!("#{id}")
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use axum::async_trait;
    use tokio::net::TcpListener;

    use crate::session::{IdSource, InitSession};

    use super::*;

    #[derive(Debug)]
    struct Id {
        _username: String,
    }
    #[derive(Debug)]
    struct Session {
        _id: Id,
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
                _username: cx.username.to_owned(),
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
            Session { _id: id }
        }
    }

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
        let router = login_router(auth_session);
        let listener = TcpListener::bind("127.0.0.1:6969")
            .await
            .expect("failed to bind");
        axum::serve(listener, router)
            .await
            .expect("failed to serve");
    }
}
