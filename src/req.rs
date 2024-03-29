use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    RequestPartsExt,
};
use axum_client_ip::SecureClientIp;
use axum_extra::{headers::Cookie, TypedHeader};
use maud::{html, Markup};
use tokio::sync::OwnedMutexGuard;

use crate::{
    session::{AuthLayerSession, AuthState},
    SESSION_KEY_COOKIE_NAME,
};

/// An extractor to help axum handlers receive a auth layer session
#[async_trait]
impl<Session, S> FromRequestParts<S> for AuthLayerSession<Session>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    S: Sync + Send,
    AuthState<Session>: FromRef<S>,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AuthState::from_ref(state);
        let SecureClientIp(client_ip): SecureClientIp = parts
            .extract()
            .await
            .map_err(|_| AuthError::NoClientIpAddr)?;
        let TypedHeader(cookie): TypedHeader<Cookie> =
            parts.extract().await.map_err(|_| AuthError::NoSessionKey)?;
        let session_key = cookie
            .get(SESSION_KEY_COOKIE_NAME)
            .ok_or(AuthError::NoSessionKey)?;
        let layer_session = state
            .layer_session(client_ip, session_key)
            .await
            .ok_or(AuthError::SessionTimeout)?;
        Ok(layer_session)
    }
}

/// An extractor to help axum handlers receive a mutable session
pub struct AuthSession<Session>(pub OwnedMutexGuard<Session>);
#[async_trait]
impl<Session, S> FromRequestParts<S> for AuthSession<Session>
where
    Session: std::fmt::Debug + Sync + Send + 'static,
    S: Sync + Send,
    AuthState<Session>: FromRef<S>,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let layer_session = AuthLayerSession::from_request_parts(parts, state).await?;
        Ok(Self(layer_session.user_session.lock_owned().await))
    }
}

#[derive(Debug)]
pub enum AuthError {
    NoSessionKey,
    SessionTimeout,
    NoClientIpAddr,
}
impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            AuthError::NoSessionKey => (StatusCode::UNAUTHORIZED, "No session key"),
            AuthError::SessionTimeout => (StatusCode::UNAUTHORIZED, "Session timed out"),
            AuthError::NoClientIpAddr => (StatusCode::UNAUTHORIZED, "No client IP address"),
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
            p {
                span { "You should log in " }
                a href="/login" { "here" }
                span { ", come back and reload this page." }
            }
        }
    }
}

/// Separate the sub-session from a global session so that libraries can focus only on the sub-session that they care about
pub trait FromAuthSession<Session> {
    fn from_mut(input: &mut AuthSession<Session>) -> &mut Self;
}
