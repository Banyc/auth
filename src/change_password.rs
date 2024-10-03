use std::{net::IpAddr, sync::Arc};

use maud::{html, Markup};
use serde::Deserialize;
use tokio::sync::oneshot;

use crate::{
    referred_id,
    session::{
        AuthSessionLayerHandler, AuthSessionLayerMessage, BasicCredential, PasswordChangeReq,
    },
};

pub const CHANGE_PASSWORD_PAGE_LINK: &str = "/change-password";
pub const CHANGE_PASSWORD_SUBMIT_LINK: &str = "/change-password/summit";
const ELEMENT_ID: &str = "change-password-form";
const SUBMIT_INDICATOR_ID: &str = "change-password-submit-indicator";

pub fn change_password_form(err_msg: &str, submit_link: &str) -> Markup {
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
pub struct ChangeForm {
    pub old_password: Arc<str>,
    pub new_password: Arc<str>,
}

#[bon::builder]
pub async fn change_password_submit<Session: Sync + Send + 'static>(
    ip_addr: Option<IpAddr>,
    form: &ChangeForm,
    username: Arc<str>,
    state: &AuthSessionLayerHandler<Session>,
    change_password_link: &str,
    change_password_submit_link: &str,
) -> Markup {
    let req = PasswordChangeReq {
        credential: BasicCredential {
            username,
            password: form.old_password.clone(),
        },
        new_password: form.new_password.clone(),
    };
    let (tx, rx) = oneshot::channel();
    state
        .request(AuthSessionLayerMessage::ChangePassword {
            req: (ip_addr, req),
            resp: tx,
        })
        .await;
    if let Err(e) = rx.await.unwrap() {
        return change_password_form(e, change_password_submit_link);
    }
    html! {
        p { "You have changed the password successfully!" }
        p {
            a href=(change_password_link) {
                "Change your password"
            }
        }
    }
}
