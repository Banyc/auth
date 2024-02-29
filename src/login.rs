use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Form,
};
use axum_client_ip::{SecureClientIp, SecureClientIpSource};
use htmx_util::base_html;
use maud::{html, Markup};
use serde::Deserialize;

use crate::{
    change_password::CHANGE_PASSWORD_URL,
    session::{AuthSessionLayer, AuthState, IdContext, LoginError},
    SESSION_KEY_COOKIE_NAME,
};

const ELEMENT_ID: &str = "login-form";
const SUBMIT_PATH: &str = "/login-summit";
const SUBMIT_INDICATOR_ID: &str = "login-submit-indicator";

pub fn login_router<Session>(
    ip_source: SecureClientIpSource,
    auth_state: Arc<AuthSessionLayer<Session>>,
) -> axum::Router
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    axum::Router::new()
        .route("/login", get(login_page))
        .route(SUBMIT_PATH, post(login_submit))
        .layer(ip_source.into_extension())
        .with_state(auth_state)
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
async fn login_submit<Session>(
    SecureClientIp(client_ip): SecureClientIp,
    State(auth_state): State<AuthState<Session>>,
    Form(form): Form<LoginForm>,
) -> (HeaderMap, Markup)
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    let cx = IdContext {
        username: &form.username,
        password: &form.password,
    };
    let session_key = match auth_state.login(client_ip, &cx).await {
        Ok(x) => x,
        Err(e) => {
            let markup = match e {
                LoginError::SessionCollision => {
                    login_form("Too many active users. Try again later.")
                }
                LoginError::WrongCreds => login_form("Wrong!"),
                LoginError::TooManyAttempts => login_form("Banned!"),
            };
            return (HeaderMap::new(), markup);
        }
    };
    let markup = html! {
        p { "You have logged in successfully!" }
        p {
            a href=(CHANGE_PASSWORD_URL) {
                "Change your password"
            }
        }
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
