use crate::{Error, Sessions, UserCtx, UserMap, WebResult};
use serde::Deserialize;
use uuid::Uuid;
use warp::Reply;

#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub name: String,
}

pub async fn member_handler(user_ctx: UserCtx) -> WebResult<impl Reply> {
    Ok(format!("Member with id {}", user_ctx.user_id))
}

pub async fn admin_handler(user_ctx: UserCtx) -> WebResult<impl Reply> {
    Ok(format!("Admin with id {}", user_ctx.user_id))
}

pub async fn login_handler(
    body: LoginRequest,
    user_map: UserMap,
    sessions: Sessions,
) -> WebResult<impl Reply> {
    let name = body.name;
    match user_map
        .read()
        .await
        .iter()
        .filter(|(_, v)| *v.name == name)
        .nth(0)
    {
        Some(v) => {
            let token = Uuid::new_v4().to_string();
            sessions
                .write()
                .await
                .insert(token.clone(), String::from(v.0));
            Ok(token)
        }
        None => Err(warp::reject::custom(Error::UserNotFoundError)),
    }
}

pub async fn logout_handler(user_ctx: UserCtx, sessions: Sessions) -> WebResult<impl Reply> {
    sessions.write().await.remove(&user_ctx.token);
    Ok("success")
}
