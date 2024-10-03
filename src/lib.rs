pub mod change_password;
pub mod login;
pub mod password;
pub mod req;
pub mod session;

pub const SESSION_KEY_COOKIE_NAME: &str = "auth-session-key";

fn referred_id(id: &str) -> String {
    format!("#{id}")
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use async_trait::async_trait;
    use axum::{
        debug_handler,
        extract::State,
        response::Html,
        routing::{get, post},
        Form, Router,
    };
    use change_password::{
        change_password_form, change_password_submit, ChangeForm, CHANGE_PASSWORD_PAGE_LINK,
        CHANGE_PASSWORD_SUBMIT_LINK,
    };
    use htmx_util::base_html;
    use http::HeaderMap;
    use login::{login_form, login_submit, LoginForm, LOGIN_PAGE_LINK, LOGIN_SUBMIT_LINK};
    use maud::html;
    use req::auth;
    use session::{AuthSessionLayer, AuthSessionLayerHandler, UserLayer};
    use tokio::net::TcpListener;

    use self::session::{BasicCredential, PasswordChangeReq};

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_on_web() {
        let user_layer = TestUserLayer::new(HashMap::new());
        let auth_state = AuthSessionLayer::new(Duration::from_secs(u64::MAX), Box::new(user_layer));
        let auth_state = AuthSessionLayerHandler::new(auth_state);
        let state = AppState { auth: auth_state };
        let state = Arc::new(state);
        let auth_router = Router::new()
            .route(LOGIN_PAGE_LINK, get(login_page))
            .route(LOGIN_SUBMIT_LINK, post(login_submit_api))
            .route(CHANGE_PASSWORD_PAGE_LINK, get(change_password_page))
            .route(
                CHANGE_PASSWORD_SUBMIT_LINK,
                post(change_password_submit_api),
            )
            .with_state(state.clone());
        let router = Router::new()
            .route("/session", get(show_session))
            .with_state(state)
            .nest("/", auth_router);
        let listener = TcpListener::bind("127.0.0.1:6969")
            .await
            .expect("failed to bind");
        axum::serve(listener, router)
            .await
            .expect("failed to serve");
    }

    async fn change_password_page(headers: HeaderMap, state: State<Arc<AppState>>) -> Html<String> {
        if let Err(e) = auth(&headers, None, &state.auth, LOGIN_SUBMIT_LINK).await {
            return Html(e.into_string());
        }
        Html(base_html(change_password_form("", CHANGE_PASSWORD_SUBMIT_LINK)).into_string())
    }
    async fn change_password_submit_api(
        headers: HeaderMap,
        state: State<Arc<AppState>>,
        form: Form<ChangeForm>,
    ) -> Html<String> {
        let session = match auth(&headers, None, &state.auth, LOGIN_SUBMIT_LINK).await {
            Ok(x) => x,
            Err(e) => {
                return Html(e.into_string());
            }
        };
        let html = change_password_submit()
            .form(&form.0)
            .state(&state.auth)
            .change_password_link(CHANGE_PASSWORD_PAGE_LINK)
            .change_password_submit_link(CHANGE_PASSWORD_SUBMIT_LINK)
            .username(session.username)
            .call()
            .await;
        Html(html.into_string())
    }
    async fn login_page() -> Html<String> {
        Html(base_html(login_form("", LOGIN_SUBMIT_LINK)).into_string())
    }
    async fn login_submit_api(
        state: State<Arc<AppState>>,
        form: Form<LoginForm>,
    ) -> (HeaderMap, Html<String>) {
        let f = |username| Session {
            id: Id { username },
        };
        let (headers, html) = login_submit()
            .form(&form.0)
            .state(&state.auth)
            .change_password_link(CHANGE_PASSWORD_PAGE_LINK)
            .login_submit_link(LOGIN_SUBMIT_LINK)
            .f(f)
            .call()
            .await;
        (headers, Html(html.into_string()))
    }
    #[debug_handler]
    async fn show_session(headers: HeaderMap, state: State<Arc<AppState>>) -> Html<String> {
        let session = match auth(&headers, None, &state.auth, LOGIN_SUBMIT_LINK).await {
            Ok(x) => x,
            Err(e) => {
                return Html(e.into_string());
            }
        };
        let username = session.user_session.id.username.to_string();
        let body = html! {
            h1 { "Session" }
            p {
                span { "Username: " }
                span { (username) }
            }
        };
        Html(base_html(body).into_string())
    }

    struct AppState {
        auth: AuthSessionLayerHandler<Session>,
    }

    #[derive(Debug)]
    struct Id {
        pub username: Arc<str>,
    }
    #[derive(Debug)]
    struct Session {
        pub id: Id,
    }

    /// Create a `Session` based on the given user credential with preset users for test
    ///
    /// This can be a database handle in production
    #[derive(Debug)]
    struct TestUserLayer {
        users: HashMap<String, String>,
    }
    impl TestUserLayer {
        pub fn new(mut users: HashMap<String, String>) -> Self {
            let new_users = [("foo", "bar")]
                .into_iter()
                .map(|(u, p)| (u.to_owned(), p.to_owned()));
            users.extend(new_users);
            Self { users }
        }
    }
    #[async_trait]
    impl UserLayer for TestUserLayer {
        /// `true`: auth successful
        async fn auth(&mut self, cx: &BasicCredential) -> bool {
            let Some(password) = self.users.get(cx.username.as_ref()) else {
                return false;
            };
            password == cx.password.as_ref()
        }
        async fn change_password(&mut self, args: &PasswordChangeReq) -> Result<(), &'static str> {
            let Some(p) = self.users.get_mut(args.credential.username.as_ref()) else {
                return Err("User not exists");
            };
            if p != args.credential.password.as_ref() {
                return Err("Wrong old password");
            }
            *p = args.new_password.to_string();
            Ok(())
        }
    }
}
