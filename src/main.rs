// TODO add secret check to question additions

use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::error::ErrorUnauthorized;
use actix_web::middleware::Logger;
use actix_web::*;
use askama::Template;

use env_logger;

use futures::future;
use std::collections::HashMap;
use std::sync::{Mutex};

use serde::{Deserialize, Serialize};

use ron;
use std::fs;
use std::io::BufReader;


use serde_json;


const AUTH_EXPIRES_MINUTES: i64 = 120;
const LETTERS: [char; 31] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
const X_HIST_LABEL_MAX_LENGTH: usize = 12;

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

type WebQuizData = web::Data<Mutex<WebQuiz>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Login {
    user_name: String,
}

#[derive(Template)]
#[template(path = "not_found.html")]
struct NotFoundTemplate{}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

async fn login(id: Identity) -> HttpResponse {
    if id.identity().is_some() {
        HttpResponse::SeeOther().header("LOCATION", "/logout").finish()
    } else {
        HttpResponse::Ok().content_type("text/html").body(
                LoginTemplate.render().unwrap()
                )
    }
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
    info: String,
    answers: Vec<(usize, String)>,
}

async fn vote_page(q_id: web::Path<usize>, quizes: WebQuizData, id: Identity) -> HttpResponse {
    let q_id = *q_id;
    if let Some(_id) = id.identity() {
        let quizes = quizes.lock().unwrap();
        println!("{}", quizes.questions.len());
        if quizes.questions.len() <= q_id {
            let document = NotFoundTemplate{}.render().unwrap(); 
            return HttpResponse::NotFound().content_type("text/html").body(document.clone());
        }
        let question = quizes.questions[q_id].question.clone();
        let info = quizes.questions[q_id].info.clone();
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
            info,
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

        if sums.len() <= q_id {
            return HttpResponse::BadRequest().finish();
        }

        let vote = if req.vote < sums[q_id].len() {
            req.vote
        } else {
            println!("BAD VOTE: {} (from {})", req.vote, id);
            return HttpResponse::BadRequest().finish();
        };
        println!("VOTED: {} (from {})", vote, id);

        let mut users_data = user_data.lock().unwrap();
        if let Some(user) = users_data.get_mut(&id) {
            // In case questions were added
            if user.voted.len() <= q_id {
                for _i in (user.voted.len() - 1)..q_id {
                    user.voted.push(None)
                }
            }

            if let Some(old_vote) = user.voted[q_id] {
                sums[q_id][old_vote] -= 1;
            }
            user.voted[q_id] = Some(vote);
            sums[q_id][vote] += 1;
        }
        HttpResponse::SeeOther().header("LOCATION", format!("/{}/results", q_id)).finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[derive(Deserialize)]
struct AddQuestion {
    question: Question,
}

async fn add_question(
    req: web::Json<AddQuestion>,
    quiz: WebQuizData,
    sums: WebVoteData,
) -> HttpResponse {
    let new_q = &req.question;
    let mut quiz = quiz.lock().unwrap();
    quiz.questions.push(new_q.clone());
    let mut sums = sums.lock().unwrap();
    sums.push(vec![0; new_q.options.len()]);

    HttpResponse::Ok().finish()
}

#[derive(Template)]
#[template(path = "plot_results.html")]
struct PlotTemplate {
    q_id: usize,
    x_array: String,
    y_array: String,
    legend: Vec<String>,
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
    } else {&
        if let Some(user) = users.lock().unwrap().get(&id.identity().unwrap()) {
            if user.voted[q_id].is_none() {
                // User tries to bypass the vote
                return HttpResponse::Ok().content_type("text/html").body(NeedToVoteToSeeResultsTemplate{q_id}.render().unwrap());
            }
        } else {
            // User login is expired probably
            // TODO return info about logout happening
            return HttpResponse::SeeOther().header("LOCATION", "/logout").finish();
        };

        let quizes = quizes.lock().unwrap();
        let options = &quizes.questions[q_id].options;
        let n_answers = options.len();
        let mut legend: Vec<String> = Vec::new();
        let x: Vec<_> = LETTERS[0..n_answers]
            .iter()
            .zip(options.iter())
            .map(|(letter, full_option)| 
                if full_option.len() < X_HIST_LABEL_MAX_LENGTH {
                    format!("\"{}\"", full_option)
                } else {
                    legend.push(format!("{}: {}", letter, full_option));
                    format!("\"{}\"", letter)
                }
            )
            .collect();
        let x = x.join(",");
        let y: Vec<_> = (0..n_answers).map(|_i| "0").collect();
        let y = y.join(",");
        let document = PlotTemplate {
            q_id,
            x_array: format!("[{}]", x),
            y_array: format!("[{}]", y),
            legend,
        }
        .render()
        .unwrap();
        HttpResponse::Ok().content_type("text/html").body(document)
    } 
}

#[derive(Template)]
#[template(path = "q_list.html")]
struct ListQuestionsTemplate {
    headers: Vec<String>,
}

async fn list_questions(
    quizes: WebQuizData,
    id: Identity,
) -> HttpResponse {
    if let None = id.identity() {
        HttpResponse::BadRequest().finish()
    } else {
        let headers = quizes.lock().unwrap()
            .questions
            .iter()
            .map(|q| q.question.clone())
            .collect();
        HttpResponse::Ok().content_type("text/html").body(
            ListQuestionsTemplate{
                headers,
            }.render().unwrap())
    }
}


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
        let quizes = quizes.lock().unwrap();
        users_data.insert(
            user_name.to_string(),
            User {
                name: req.user_name.clone(),
                voted: vec![None; quizes.questions.len()],
            },
        );
        println!("New user: {}", user_name);

        HttpResponse::SeeOther().header("LOCATION", "/list").finish()
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
    HttpResponse::SeeOther().header("LOCATION", "/").finish()
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

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Question {
    question: String,
    info: String,
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
    let quizes = WebQuiz::from_ron("test.quiz.ron")?;
    let votes: WebVoteData = web::Data::new(Mutex::new(quizes.make_vote_data()));

    {
        let q = &quizes.questions[0];
        println!("{}", serde_json::to_string(q).unwrap());
    }

    let quizes = web::Data::new(Mutex::new(quizes));

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(move || {
        App::new()
            .app_data(quizes.clone())
            .app_data(users_data.clone())
            .app_data(votes.clone())
            .wrap(Logger::new("%a %t %r Response: %s"))
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-cookie")
                    .max_age(AUTH_EXPIRES_MINUTES * 60) // seconds
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
            .service(
                web::resource("/quest_mod")
                    .guard(guard::Post())
                    .route(web::post().to(add_question))
            )
            .service(
                web::resource("/list")
                    .guard(guard::Get())
                    .route(web::get().to(list_questions))
            )
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
