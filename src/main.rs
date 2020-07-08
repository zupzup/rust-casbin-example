use casbin::prelude::*;
use std::collections::HashMap;
use std::convert::Infallible;
use std::str::from_utf8;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use warp::{
    filters::header::headers_cloned,
    filters::method::method,
    filters::path::{full, FullPath},
    http::{header::AUTHORIZATION, method::Method, HeaderMap, HeaderValue},
    Filter, Rejection, Reply,
};

type UserMap = Arc<RwLock<HashMap<String, String>>>;
type WebResult<T> = std::result::Result<T, Rejection>;
type Result<T> = std::result::Result<T, Error>;
type SharedEnforcer = Arc<Enforcer>;

const BEARER_PREFIX: &str = "Bearer ";

const MODEL_PATH: &str = "./auth/auth_model.conf";
const POLICY_PATH: &str = "./auth/policy.csv";

#[tokio::main]
async fn main() {
    let user_map = Arc::new(RwLock::new(create_user_map()));
    let enforcer = Arc::new(
        Enforcer::new(MODEL_PATH, POLICY_PATH)
            .await
            .expect("can read casbin model and policy files"),
    );

    let base_route = warp::path!("yay")
        .and(with_auth(enforcer.clone(), user_map.clone()))
        .and_then(base_handler);
    let routes = base_route;

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}

fn create_user_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(String::from("ABCD1234"), String::from("21"));
    map.insert(String::from("7777HHHH"), String::from("100"));
    map.insert(String::from("9999BBBB"), String::from("1"));
    map
}

async fn base_handler(user_id: String) -> WebResult<impl Reply> {
    Ok("hello")
}

fn with_auth(
    enforcer: SharedEnforcer,
    user_map: UserMap,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    full()
        .and(headers_cloned())
        .and(method())
        .map(
            move |path: FullPath, headers: HeaderMap<HeaderValue>, method: Method| {
                (path, enforcer.clone(), headers, method, user_map.clone())
            },
        )
        .and_then(user_authentication)
}

async fn user_authentication(
    args: (
        FullPath,
        SharedEnforcer,
        HeaderMap<HeaderValue>,
        Method,
        UserMap,
    ),
) -> WebResult<String> {
    let path = args.0;
    let enforcer = args.1;
    let headers = args.2;
    let method = args.3;
    let user_map = args.4;

    let token = token_from_header(&headers).map_err(|e| warp::reject::custom(e))?;
    let user_id = match user_map.read().await.get(&token) {
        Some(v) => v.clone(),
        None => return Err(warp::reject::custom(Error::InvalidTokenError)),
    };
    // TODO: use path and method to enforce
    enforcer
        .enforce(&[&user_id.as_str(), &path.as_str(), &method.as_str()])
        .await
        .expect("works"); // TODO: handle error properly
    Ok(String::default())
}

fn token_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return Err(Error::NoAuthHeaderFoundError),
    };
    let auth_header = match from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Err(Error::NoAuthHeaderFoundError),
    };
    if !auth_header.starts_with(BEARER_PREFIX) {
        return Err(Error::InvalidAuthHeaderFormatError);
    }
    let without_prefix = auth_header.trim_start_matches(BEARER_PREFIX);
    Ok(without_prefix.to_owned())
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error")]
    SomeError(),
    #[error("no authorization header found")]
    NoAuthHeaderFoundError,
    #[error("wrong authorization header format")]
    InvalidAuthHeaderFormatError,
    #[error("no user found for this token")]
    InvalidTokenError,
}

impl warp::reject::Reject for Error {}
