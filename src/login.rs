use std::{net::IpAddr, sync::Arc};

use http::HeaderMap;
use maud::{html, Markup};
use serde::Deserialize;
use tokio::sync::oneshot;

use crate::{
    referred_id,
    session::{AuthSessionLayerHandler, AuthSessionLayerMessage, BasicCredential},
    SESSION_KEY_COOKIE_NAME,
};

pub const LOGIN_PAGE_LINK: &str = "/login";
pub const LOGIN_SUBMIT_LINK: &str = "/login/summit";
const ELEMENT_ID: &str = "login-form";
const SUBMIT_INDICATOR_ID: &str = "login-submit-indicator";

pub fn login_form(err_msg: &str, submit_link: &str) -> Markup {
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
                    hx-post=(submit_link)
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
pub struct LoginForm {
    pub username: Arc<str>,
    pub password: Arc<str>,
}

#[bon::builder]
pub async fn login_submit<Session: Sync + Send + 'static>(
    ip_addr: Option<IpAddr>,
    form: &LoginForm,
    state: &AuthSessionLayerHandler<Session>,
    login_submit_link: &str,
    change_password_link: &str,
    f: Box<dyn FnOnce() -> Session + Send>,
) -> (HeaderMap, Markup) {
    let credential = BasicCredential {
        username: form.username.clone(),
        password: form.password.clone(),
    };
    let (tx, rx) = oneshot::channel();
    state
        .request(AuthSessionLayerMessage::Login {
            req: (ip_addr, credential, f),
            resp: tx,
        })
        .await;
    let resp = rx.await.unwrap();
    match resp {
        Ok(session_key) => {
            let markup = html! {
                p { "You have logged in successfully!" }
                p {
                    a href=(change_password_link) {
                        "Change your password"
                    }
                }
            };
            let mut header = HeaderMap::new();
            header.insert(
                "Set-Cookie",
                format!("{SESSION_KEY_COOKIE_NAME}={session_key}; SameSite=None; Secure; Path=/")
                    .parse()
                    .unwrap(),
            );
            (header, markup)
        }
        Err(e) => (
            HeaderMap::new(),
            login_form(&format!("{e}"), login_submit_link),
        ),
    }
}
