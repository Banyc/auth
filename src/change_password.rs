use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Form,
};
use axum_client_ip::{SecureClientIp, SecureClientIpSource};
use htmx_util::base_html;
use maud::{html, Markup};
use serde::Deserialize;

use crate::session::{AuthLayerSession, AuthSessionLayer, AuthState, ChangePasswordContext};

pub const CHANGE_PASSWORD_URL: &str = "/change-password";
const ELEMENT_ID: &str = "change-password-form";
const SUBMIT_PATH: &str = "/change-password-summit";
const SUBMIT_INDICATOR_ID: &str = "change-password-submit-indicator";

pub fn change_password_router<Session>(
    ip_source: SecureClientIpSource,
    auth_state: Arc<AuthSessionLayer<Session>>,
) -> axum::Router
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    axum::Router::new()
        .route(CHANGE_PASSWORD_URL, get(change_password_page))
        .route(SUBMIT_PATH, post(change_password_submit))
        .layer(ip_source.into_extension())
        .with_state(auth_state)
}

/// Show the password changing page
async fn change_password_page<Session>(_: AuthLayerSession<Session>) -> Markup {
    let form = change_password_form("");
    base_html(form)
}

fn change_password_form(err_msg: &str) -> Markup {
    html! {
        div id=(ELEMENT_ID) {
            form {
                h1 { "Change password" }
                input type="password" name="old_password" placeholder="old password" {}
                br {}
                input type="password" name="new_password" placeholder="new password" {}
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
struct ChangeForm {
    pub old_password: String,
    pub new_password: String,
}
async fn change_password_submit<Session>(
    SecureClientIp(client_ip): SecureClientIp,
    auth_layer_session: AuthLayerSession<Session>,
    State(auth_state): State<AuthState<Session>>,
    Form(form): Form<ChangeForm>,
) -> impl IntoResponse
where
    Session: std::fmt::Debug + Sync + Send + 'static,
{
    let cx = ChangePasswordContext {
        old_password: &form.old_password,
        new_password: &form.new_password,
    };
    match auth_state
        .change_password(client_ip, &auth_layer_session.username, &cx)
        .await
    {
        Ok(()) => (),
        Err(e) => {
            return change_password_form(e);
        }
    }

    html! {
        p { "You have changed the password successfully!" }
        p {
            a href=(CHANGE_PASSWORD_URL) {
                "Change your password"
            }
        }
    }
}

fn referred_id(id: &str) -> String {
    format!("#{id}")
}
