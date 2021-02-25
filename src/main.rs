// TODO voting system is a joke
// TODO cookie expire
// TODO add buttons, etc
// TODO better logs 
// TODO redirect after vote, login

use actix_web::*;
use actix_identity::{Identity, CookieIdentityPolicy, IdentityService};
use actix_web::middleware::Logger;
use actix_web::error::ErrorUnauthorized;
use actix_files::Files;

use askama::Template;

use env_logger;

use futures::future;
use std::sync::{Mutex};
use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Answer {
    A,
    B,
    C,
    D
}

impl TryFrom<&str> for Answer {
    type Error = &'static str;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "A" => Ok(Answer::A),
            "B" => Ok(Answer::B),
            "C" => Ok(Answer::C),
            "D" => Ok(Answer::D),
            _ => Err("No!"),
        }
    }
}


#[derive(Debug, Clone, Deserialize)]
struct User {
    name: String,
    voted: Option<Answer>,
}

type UsersData = Mutex<HashMap<String, User>>;
type WebUsersData = web::Data<UsersData>;

impl FromRequest for User {
    type Error = Error;
    type Future = future::Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, payload: &mut dev::Payload) -> Self::Future {
        if let Ok(id) = Identity::from_request(req, payload).into_inner() {
            if let Some(id) = id.identity() {
                if let Some(users) = req.app_data::<UsersData>() {
                    if let Some(user) = users.lock().unwrap().get(&id).cloned() {
                        return future::ready(Ok(user));
                    }
                }
            }
        }
        future::ready(Err(ErrorUnauthorized("")))
    }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
struct Login {
    user_name: String
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

async fn login(id: Identity) -> Result<HttpResponse> {
    let s = if let Some(id) = id.identity() {
        format!("Logged in as {}.", id)
    } else {
        // login form
        LoginTemplate.render().unwrap()
    };
    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Vote {
    vote: String
}

#[derive(Template)]
#[template(path = "vote.html")]
struct VoteTemplate;

async fn vote_page(id: Identity) -> HttpResponse {
    if let Some(id) = id.identity() {
        HttpResponse::Ok().content_type("text/html").body(
        VoteTemplate.render().unwrap())
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn vote(req: web::Form<Vote>, data: WebUsersData, id: Identity) -> HttpResponse {
    let vote = &req.vote;
    println!("VOTED: {}", vote);
    if !(["A", "B", "C", "D"].contains(&vote.as_str())) {
        return HttpResponse::BadRequest().finish();
    }
    let id = id.identity().unwrap();
    let mut users_data = data.lock().unwrap();
    if let Some(user) = users_data.get_mut(&id) {
        user.voted = Some(Answer::try_from(vote.as_str()).unwrap());
    }
    HttpResponse::Ok().finish()
}

async fn new_login(req: web::Form<Login>, data: WebUsersData, id: Identity) -> HttpResponse {
    let user_name = &req.user_name;
    let mut users_data = data.lock().unwrap();
    if users_data.contains_key(user_name) {
        println!("Attempted login with used username: {}", user_name);
        HttpResponse::Ok().content_type("text/html").body("Name already in use!")
    } else {
        id.remember(user_name.to_string());
        users_data.insert(user_name.to_string(), User { name : req.user_name.clone(), voted: None });
        println!("New user: {}", user_name);
        HttpResponse::Ok().content_type("text/html").body("Succesfully logged in")
    }
}

async fn logout(data: WebUsersData, id: Identity) -> HttpResponse {
    if let Some(user_name) = id.identity() {
        id.forget();
        let mut data = data.lock().unwrap();
        data.remove(&user_name);
    }
    HttpResponse::Ok().finish()
}

#[derive(Serialize, Default)]
struct PlotData {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

async fn plot_update(data: WebUsersData, id: Identity) -> Result<web::Json<PlotData>> {
    if let Some(_id) = id.identity() {
        let mut stats = PlotData::default();
        for (_, user) in data.lock().unwrap().iter() {
            match user.voted {
                Some(Answer::A) => { stats.a += 1; },
                Some(Answer::B) => { stats.b += 1; },
                Some(Answer::C) => { stats.c += 1; },
                Some(Answer::D) => { stats.d += 1; },
                None => {}, 
            }
        }
        Ok(web::Json(stats))
    } else {
        Err(ErrorUnauthorized(""))
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let users_data: WebUsersData = web::Data::new(Mutex::new(HashMap::new()));

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(move || {
        App::new()
            .app_data(users_data.clone())
            .wrap(Logger::new("%a %t %r Response: %s"))
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                .name("auth-cookie")
                .secure(false)))
            .service(web::resource("/logout").to(logout))
            .service(Files::new("/results", "./static").index_file("index.html").prefer_utf8(true))
            .service(
                web::resource("/")
                    .guard(guard::Post())
                    .route(web::post().to(new_login)))
            .service(
                web::resource("/")
                    .guard(guard::Get())
                    .route(web::get().to(login)))
            .service(
                web::resource("/vote")
                .guard(guard::Post())
                .route(web::post().to(vote)))
            .service(
                web::resource("/vote")
                .guard(guard::Get())
                .route(web::get().to(vote_page)))
            .service(
                web::resource("/plot_update")
                .guard(guard::Get())
                .route(web::get().to(plot_update)))
    }).bind("127.0.0.1:8080")?
    .run()
    .await
}
