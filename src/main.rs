use actix_web::{ get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder };
use elasticsearch::{ Elasticsearch, SearchParts, http::transport::Transport, IndexParts };
use serde_json::{ json, Value };
use serde::{ Deserialize, Serialize };
use std::error::Error;
use jsonwebtoken::{ decode, DecodingKey, Validation, Algorithm };
use firestore::*;
use tokio::sync::OnceCell;
use google_cloud_auth::credentials::CredentialsFile;
use google_cloud_storage::client::{ Client, ClientConfig };
use google_cloud_storage::sign::SignedURLOptions;

static DB_INSTANCE: OnceCell<FirestoreDb> = OnceCell::const_new();
static STORAGE_CLIENT: OnceCell<Client> = OnceCell::const_new();

async fn initialize_storage() -> Client {
    let credentials = CredentialsFile::new_from_file(
        "sa-credentials/sa-credentials.json".to_string()
    ).await.expect("Failed");

    let config = ClientConfig::default().with_credentials(credentials).await.unwrap();
    Client::new(config)
}

async fn get_storage_client() -> &'static Client {
    STORAGE_CLIENT.get_or_init(initialize_storage).await
}

async fn get_file_signed_url(file_name: &str) -> Result<String, Box<dyn Error>> {
    let client = get_storage_client().await;

    let signed_url = client
        .signed_url(
            "cat-of-the-week-bucket-01",
            file_name,
            None,
            None,
            SignedURLOptions::default()
        ).await
        .expect("Signed url error");

    Ok(signed_url)
}

async fn initialize_db() -> FirestoreDb {
    let options: FirestoreDbOptions = FirestoreDbOptions {
        google_project_id: "cat-of-the-week-2024".to_string(),
        database_id: "cat-of-the-week-insights01".to_string(),
        max_retries: 3,
        firebase_api_url: None,
    };

    FirestoreDb::with_options_service_account_key_file(
        options,
        "sa-credentials/sa-credentials.json".into()
    ).await.expect("Failed to initialize FirestoreDb")
}

async fn get_db_instance() -> &'static FirestoreDb {
    DB_INSTANCE.get_or_init(initialize_db).await
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Image {
    // id: String,
    file_name: String,
}

#[derive(Serialize, Deserialize)]
struct Vote {
    cat_id: String,
    vote: String,
}

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

async fn select_image_file_name_by_id(image_id: &str) -> Result<String, Box<dyn Error>> {
    let db = get_db_instance().await;

    const TEST_COLLECTION_NAME: &'static str = "Images";

    let obj_by_id: Option<Image> = db
        .fluent()
        .select()
        .by_id_in(TEST_COLLECTION_NAME)
        .obj()
        .one(image_id).await?;

    println!("{:?}", obj_by_id);

    let image = obj_by_id.unwrap();
    let file_name = image.file_name.clone();

    Ok(file_name)
}

#[derive(Debug, Serialize, Deserialize)]
struct Cat {
    birth_date: String,
    breed: String,
    color: String,
    created_on: String,
    dislikes: u32,
    dislikes_voted_users_ids: Vec<String>,
    id: String,
    likes: u32,
    likes_voted_users_ids: Vec<String>,
    microchip: String,
    name: String,
    photo_id: String,
    votes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct CatDoc {
    _source: Cat,
    _id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CatWithImage {
    birth_date: String,
    breed: String,
    color: String,
    created_on: String,
    dislikes: u32,
    dislikes_voted_users_ids: Vec<String>,
    id: String,
    likes: u32,
    likes_voted_users_ids: Vec<String>,
    microchip: String,
    name: String,
    photo_id: String,
    votes: u32,
    image_url: String, // New field
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // This is the user ID
    exp: usize, // Expiration time (as an example)
}

async fn search_cat_by_id(cat_id: &str) -> Result<(Cat, String), Box<dyn Error>> {
    let transport = Transport::single_node("http://localhost:9200")?;
    let client = Elasticsearch::new(transport);

    let response = client
        .search(SearchParts::Index(&["current-round-cats"]))
        .body(json!({"query": {"term": {"id": cat_id}}}))
        .send().await?;

    let response_body = response.json::<Value>().await?;

    println!("{:?}", response_body["hits"]["hits"]);

    let cat_doc: CatDoc = serde_json::from_value(response_body["hits"]["hits"][0].clone())?;

    let cat: Cat = cat_doc._source;
    let doc_id_value = cat_doc._id;
    println!("{}", doc_id_value);
    let doc_id = doc_id_value.to_string();

    Ok((cat, doc_id))
}

async fn replace_cat(cat: &Cat, doc_id: &str) -> Result<(), Box<dyn Error>> {
    println!("{}", &doc_id);

    let transport = Transport::single_node("http://localhost:9200")?;
    let client = Elasticsearch::new(transport);

    let response = client
        .index(IndexParts::IndexId(&"current-round-cats", doc_id))
        .body(json!(cat))
        .refresh(elasticsearch::params::Refresh::True)
        .send().await?;

    println!("{}", response.status_code());

    Ok(())
}

async fn search(user_id: &str) -> Result<Cat, Box<dyn Error>> {
    let transport = Transport::single_node("http://localhost:9200")?;
    let client = Elasticsearch::new(transport);

    let response = client
        .search(SearchParts::Index(&["current-round-cats"]))
        .size(1)
        .body(
            json!({
            "query": {"bool": {
            "must_not": [
                {"term": {"likes_voted_users_ids": user_id}},
                {"term": {"dislikes_voted_users_ids": user_id}}
            ]
            }},
            "sort": [{"votes": {"order": "asc"}}]
        })
        )
        .send().await?;

    let response_body = response.json::<Value>().await?;
    println!("{:?}", response_body["hits"]["hits"]);

    let cat: Cat = serde_json::from_value(response_body["hits"]["hits"][0]["_source"].clone())?;

    Ok(cat)
}

#[get("/cats/cat-for-vote")]
async fn cat_for_vote(req: HttpRequest) -> impl Responder {
    let auth_header = req.headers().get("Authorization");

    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            let token = auth_str.trim_start_matches("Bearer ");

            let validation = Validation::new(Algorithm::HS256);
            let decoding_key = DecodingKey::from_secret(b"aweiofj902309ufgOKJO");

            match decode::<Claims>(token, &decoding_key, &validation) {
                Ok(token_data) => {
                    let user_id = token_data.claims.sub;
                    println!("{user_id}");
                    match search(&user_id).await {
                        Ok(cat) => {
                            let image_id = &cat.photo_id;
                            match select_image_file_name_by_id(image_id).await {
                                Ok(file_name) => {
                                    println!("Success on select image");
                                    match get_file_signed_url(&file_name).await {
                                        Ok(siged_url) => {
                                            let cat_with_image = CatWithImage {
                                                birth_date: cat.birth_date,
                                                breed: cat.breed,
                                                color: cat.color,
                                                created_on: cat.created_on,
                                                dislikes: cat.dislikes,
                                                dislikes_voted_users_ids: cat.dislikes_voted_users_ids,
                                                id: cat.id,
                                                likes: cat.likes,
                                                likes_voted_users_ids: cat.likes_voted_users_ids,
                                                microchip: cat.microchip,
                                                name: cat.name,
                                                photo_id: cat.photo_id,
                                                votes: cat.votes,
                                                image_url: siged_url,
                                            };
                                            HttpResponse::Ok().json(cat_with_image)
                                        }
                                        Err(_) =>
                                            HttpResponse::InternalServerError().body(
                                                "Can not create signed URL"
                                            ),
                                    }
                                }
                                Err(err) =>
                                    HttpResponse::InternalServerError().body(
                                        format!("Error: {}", err)
                                    ),
                            }
                        }
                        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
                    }
                }
                Err(_) => HttpResponse::Unauthorized().body("Invalid token"),
            }
        } else {
            HttpResponse::Unauthorized().body("Invalid Authorization header")
        }
    } else {
        HttpResponse::Unauthorized().body("Authorization header missing")
    }
}

#[post("/vote")]
async fn vote(body: web::Bytes, req: HttpRequest) -> impl Responder {
    let auth_header = req.headers().get("Authorization");

    match serde_json::from_slice::<Vote>(&body) {
        Ok(vote_data) => {
            if let Some(auth_value) = auth_header {
                if let Ok(auth_str) = auth_value.to_str() {
                    let token = auth_str.trim_start_matches("Bearer ");

                    let validation = Validation::new(Algorithm::HS256);
                    let decoding_key = DecodingKey::from_secret(b"aweiofj902309ufgOKJO");

                    match decode::<Claims>(token, &decoding_key, &validation) {
                        Ok(token_data) => {
                            let user_id = token_data.claims.sub;

                            print!("{}", user_id);

                            match search_cat_by_id(&vote_data.cat_id).await {
                                Ok(cat_data) => {
                                    let mut cat = cat_data.0;
                                    let doc_id = cat_data.1;

                                    let is_user_id_in_likes = cat.likes_voted_users_ids.contains(
                                        &user_id
                                    );
                                    let is_user_id_in_dislikes =
                                        cat.dislikes_voted_users_ids.contains(&user_id);

                                    if is_user_id_in_likes || is_user_id_in_dislikes {
                                        HttpResponse::BadRequest().body(
                                            "You already voted for this cat!"
                                        )
                                    } else {
                                        cat.votes = cat.votes + 1;

                                        let vote = vote_data.vote;

                                        if vote == "like" {
                                            cat.likes = cat.likes + 1;
                                            cat.likes_voted_users_ids.push(user_id);
                                        } else {
                                            cat.dislikes = cat.dislikes + 1;
                                            cat.dislikes_voted_users_ids.push(user_id);
                                        }

                                        match replace_cat(&cat, &doc_id).await {
                                            Ok(_) => HttpResponse::Ok().body("OK"),
                                            Err(_) =>
                                                HttpResponse::InternalServerError().body(
                                                    "Cat not replaced"
                                                ),
                                        }
                                    }
                                }
                                Err(_) =>
                                    HttpResponse::InternalServerError().body(
                                        "Cat not find this cat"
                                    ),
                            }
                        }
                        Err(_) => HttpResponse::Unauthorized().body("Invalid token"),
                    }
                } else {
                    HttpResponse::Unauthorized().body("Invalid Authorization header")
                }
            } else {
                HttpResponse::Unauthorized().body("Authorization header missing")
            }
        }
        Err(_) => HttpResponse::BadRequest().body("Bad request!"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| { App::new().service(cat_for_vote).service(vote) })
        .bind(("127.0.0.1", 8080))?
        .workers(4)
        .run().await
}
