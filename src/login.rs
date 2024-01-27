use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Form,
};
use maud::{html, Markup};
use serde::Deserialize;

use crate::{
    htmx::base_html,
    session::{AuthSessionLayer, IdContext, LoginError},
    SESSION_KEY_COOKIE_NAME,
};

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
    base_html(form)
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
        format!("{SESSION_KEY_COOKIE_NAME}={session_key}; SameSite=None; Secure")
            .parse()
            .unwrap(),
    );
    (header, markup)
}

fn referred_id(id: &str) -> String {
    format!("#{id}")
}