// TODO better logs
// TODO redirect after vote, login

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::error::ErrorUnauthorized;
use actix_web::middleware::Logger;
use actix_web::*;
use askama::Template;

use env_logger;

use futures::future;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use ron;
use std::fs;
use std::io::BufReader;

const AUTH_MINUTES: i64 = 1;
const LETTERS: [char; 31] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

#[derive(Debug, Clone, Deserialize)]
struct User {
    name: String,
    voted: Vec<Option<usize>>,
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

// inner vec index is the answer, outer index is the quiz
type VoteData = Mutex<Vec<Vec<usize>>>;
type WebVoteData = web::Data<VoteData>;

type WebQuizData = web::Data<Arc<WebQuiz>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Login {
    user_name: String,
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
    vote: usize,
}

#[derive(Template)]
#[template(path = "vote.html")]
struct VoteTemplate {
    q_id: usize,
    question: String,
    answers: Vec<(usize, String)>,
}

async fn vote_page(q_id: web::Path<usize>, quizes: WebQuizData, id: Identity) -> HttpResponse {
    let q_id = *q_id;
    if let Some(_id) = id.identity() {
        let question = quizes.questions[q_id].question.clone();
        let answers = quizes.questions[q_id].options
            .iter()
            .cloned()
            .zip(LETTERS.iter())
            .map(|(a, l)| format!("{}: {}", l, a))
            .enumerate()
            .collect();
        let document = VoteTemplate { 
            q_id,
            question,
            answers,
        }.render().unwrap();

        HttpResponse::Ok().content_type("text/html").body(document.clone())
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn submit_vote(
    web::Path(q_id): web::Path<usize>,
    req: web::Form<Vote>,
    user_data: WebUsersData,
    sums: WebVoteData,
    id: Identity,
) -> HttpResponse {
    if let Some(id) = id.identity() {
        let mut sums = sums.lock().unwrap();

        let vote = if req.vote < sums[q_id].len() {
            req.vote
        } else {
            println!("BAD VOTE: {} (from {})", req.vote, id);
            return HttpResponse::BadRequest().finish();
        };
        println!("VOTED: {} (from {})", vote, id);

        let mut users_data = user_data.lock().unwrap();
        if let Some(user) = users_data.get_mut(&id) {
            if let Some(old_vote) = user.voted[q_id] {
                sums[q_id][old_vote] -= 1;
            }
            user.voted[q_id] = Some(vote);
            sums[q_id][vote] += 1;
        }
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[derive(Template)]
#[template(path = "plot_results.html")]
struct PlotTemplate {
    x_array: String,
    y_array: String,
}

#[derive(Template)]
#[template(path = "need_to_vote_first.html")]
struct NeedToVoteToSeeResultsTemplate {
    q_id: usize
}

async fn plot_results(
    web::Path(q_id): web::Path<usize>,
    quizes: WebQuizData,
    users: WebUsersData,
    id: Identity,
) -> HttpResponse {
    if let None = id.identity() {
        HttpResponse::BadRequest().finish()
    } else {
        if users.lock().unwrap().get(&id.identity().unwrap()).and_then(|user| user.voted[q_id]).is_none() {
            return HttpResponse::Ok().content_type("text/html").body(NeedToVoteToSeeResultsTemplate{q_id}.render().unwrap());
        }

        let n_answers = quizes.questions[q_id].options.len();
        let x: Vec<_> = LETTERS[0..n_answers]
            .iter()
            .map(|i| format!("\"{}\"", i))
            .collect();
        let x = x.join(",");
        let y: Vec<_> = (0..n_answers).map(|_i| "0").collect();
        let y = y.join(",");
        let document = PlotTemplate {
            x_array: format!("[{}]", x),
            y_array: format!("[{}]", y),
        }
        .render()
        .unwrap();
        HttpResponse::Ok().content_type("text/html").body(document)
    }
}

#[derive(Template)]
#[template(path = "after_ok_login.html")]
struct AfterOkLoginTemplate;

async fn new_login(
    req: web::Form<Login>,
    user_data: WebUsersData,
    quizes: WebQuizData,
    id: Identity,
) -> HttpResponse {
    let user_name = &req.user_name;
    let mut users_data = user_data.lock().unwrap();
    if users_data.contains_key(user_name) {
        println!("Attempted login with used username: {}", user_name);
        HttpResponse::Ok()
            .content_type("text/html")
            .body("Name already in use!")
    } else {
        id.remember(user_name.to_string());
        users_data.insert(
            user_name.to_string(),
            User {
                name: req.user_name.clone(),
                voted: vec![None; quizes.questions.len()],
            },
        );
        println!("New user: {}", user_name);

        HttpResponse::Ok().content_type("text/html").body(AfterOkLoginTemplate{}.render().unwrap())
    }
}

async fn logout(user_data: WebUsersData, sums: WebVoteData, id: Identity) -> HttpResponse {
    if let Some(user) = id.identity() {
        id.forget();
        let mut user_data = user_data.lock().unwrap();
        let mut sums = sums.lock().unwrap();
        for i in 0..(sums.len()) {
            if let Some(a) = user_data.get(&user).and_then(|x| x.voted[i]) {
                sums[i][a] -= 1;
            }
        }
        user_data.remove(&user);
    }
    HttpResponse::Ok().finish()
}

async fn plot_update(
    web::Path(q_id): web::Path<usize>,
    sums: WebVoteData,
    id: Identity,
) -> Result<web::Json<Vec<usize>>> {
    if let Some(_id) = id.identity() {
        let data = &sums.lock().unwrap()[q_id];
        let mut stats = Vec::with_capacity(data.len());
        for n in data {
            stats.push(*n);
        }
        Ok(web::Json(stats))
    } else {
        Err(ErrorUnauthorized(""))
    }
}

#[derive(Debug, Deserialize, Clone)]
struct Question {
    question: String,
    options: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct WebQuiz {
    questions: Vec<Question>,
}

impl WebQuiz {
    fn from_ron(filename: &str) -> std::io::Result<Self> {
        let file = fs::File::open(filename)?;
        let reader = BufReader::new(file);
        match ron::de::from_reader(reader) {
            Ok(x) => Ok(x),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Somebody messed with your ron file, bro!",
            )),
        }
    }

    fn make_vote_data(&self) -> Vec<Vec<usize>> {
        let mut votes = Vec::with_capacity(self.questions.len());
        for q in &self.questions {
            votes.push(vec![0; q.options.len()]);
        }
        votes
    }
}

#[derive(Template)]
#[template(path = "style.html")]
struct StyleTemplate;

async fn style() -> HttpResponse {
    HttpResponse::Ok().content_type("text/css").body(StyleTemplate{}.render().unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let users_data: WebUsersData = web::Data::new(Mutex::new(HashMap::new()));
    let quizes = WebQuiz::from_ron("test.quiz")?;
    let votes: WebVoteData = web::Data::new(Mutex::new(quizes.make_vote_data()));
    let quizes = Arc::new(quizes);

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(move || {
        App::new()
            .data(quizes.clone())
            .app_data(users_data.clone())
            .app_data(votes.clone())
            .wrap(Logger::new("%a %t %r Response: %s"))
            .wrap(IdentityService::new(
                    //TODO expiration
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .max_age(AUTH_MINUTES * 60) // seconds
                    .secure(false),
            ))
            .service(web::resource("/style").to(style))
            .service(web::resource("/logout").to(logout))
            .service(
                web::resource("/")
                    .guard(guard::Post())
                    .route(web::post().to(new_login)),
            )
            .service(
                web::resource("/")
                    .guard(guard::Get())
                    .route(web::get().to(login)),
            )
            .service(
                web::resource("/{q_id}/vote")
                    .guard(guard::Post())
                    .route(web::post().to(submit_vote)),
            )
            .service(
                web::resource("/{q_id}/vote")
                    .guard(guard::Get())
                    .route(web::get().to(vote_page)),
            )
            .service(
                web::resource("/{q_id}/results")
                    .guard(guard::Get())
                    .route(web::get().to(plot_results)),
            )
            .service(
                web::resource("{q_id}/plot_update")
                    .guard(guard::Get())
                    .route(web::get().to(plot_update)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
