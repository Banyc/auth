use std::{net::IpAddr, sync::Arc};

use headers::{Cookie, HeaderMapExt};
use htmx_util::base_html;
use http::HeaderMap;
use maud::Markup;
use thiserror::Error;
use tokio::sync::oneshot;

use crate::{
    login::login_form,
    session::{AuthSession, AuthSessionLayerHandler, AuthSessionLayerMessage},
    SESSION_KEY_COOKIE_NAME,
};

pub async fn auth<Session: Sync + Send + 'static>(
    headers: &HeaderMap,
    layer: &AuthSessionLayerHandler<Session>,
    login_submit_link: &str,
) -> Result<AuthSession<Session>, Markup> {
    auth2_(headers, layer)
        .await
        .map_err(|e| base_html(login_form(&format!("{e}"), login_submit_link)))
}
async fn auth1_<Session: Sync + Send + 'static>(
    client_ip: Option<IpAddr>,
    session_key: Option<Arc<str>>,
    layer: &AuthSessionLayerHandler<Session>,
) -> Result<AuthSession<Session>, AuthError> {
    let session_key = session_key.ok_or(AuthError::NoSessionKey)?;
    let (tx, rx) = oneshot::channel();
    layer
        .request(AuthSessionLayerMessage::Session {
            req: (client_ip, session_key),
            resp: tx,
        })
        .await;
    let session = rx.await.unwrap().ok_or(AuthError::SessionTimeout)?;
    Ok(session)
}
async fn auth2_<Session: Sync + Send + 'static>(
    headers: &HeaderMap,
    layer: &AuthSessionLayerHandler<Session>,
) -> Result<AuthSession<Session>, AuthError> {
    let cookie = headers
        .typed_get::<Cookie>()
        .ok_or(AuthError::NoSessionKey)?;
    let session_key = cookie
        .get(SESSION_KEY_COOKIE_NAME)
        .ok_or(AuthError::NoSessionKey)?;
    auth1_(None, Some(session_key.into()), layer).await
}

#[derive(Debug, Error)]
enum AuthError {
    #[error("No session key")]
    NoSessionKey,
    #[error("Session timed out")]
    SessionTimeout,
}
