use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    RequestPartsExt,
};
use axum_extra::{headers::Cookie, TypedHeader};
use maud::{html, Markup};
use tokio::sync::OwnedMutexGuard;

use crate::{session::AuthSessionLayer, SESSION_KEY_COOKIE_NAME};

pub struct PulledSession<Session>(pub OwnedMutexGuard<Session>);
#[async_trait]
impl<Session, Id> FromRequestParts<Arc<AuthSessionLayer<Session, Id>>> for PulledSession<Session>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    Id: std::fmt::Debug + Sync + Send + 'static,
{
    type Rejection = AuthError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AuthSessionLayer<Session, Id>>,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(cookie): TypedHeader<Cookie> =
            parts.extract().await.map_err(|_| AuthError::NoSessionKey)?;
        let session_key = cookie
            .get(SESSION_KEY_COOKIE_NAME)
            .ok_or(AuthError::NoSessionKey)?;
        let session = state
            .get_mut(session_key)
            .await
            .ok_or(AuthError::SessionTimeout)?;
        Ok(Self(session))
    }
}

#[derive(Debug)]
pub enum AuthError {
    NoSessionKey,
    SessionTimeout,
}
impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AuthError::NoSessionKey => (StatusCode::UNAUTHORIZED, "No session key"),
            AuthError::SessionTimeout => (StatusCode::UNAUTHORIZED, "Session timed out"),
        };
        let markup = error_page(msg);
        (status, markup).into_response()
    }
}

fn error_page(msg: &str) -> Markup {
    html! {
        h1 { "Error" }
        body {
            p { (msg) }
        }
    }
}