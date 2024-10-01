use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use std::{env, str};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;
use tlsn_core::{commitment::CommitmentKind, proof::TlsProof};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

// Setting of the application server
const SERVER_DOMAIN: &str = "api.anthropic.com";
const ROUTE: &str = "v1/chat/completions";

// Setting of the notary server — make sure these are the same with the config in ../../../notary/server
const NOTARY_HOST: &str = "0.0.0.0";
const NOTARY_PORT: u16 = 7047;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load secret variables from environment for OpenAI API connection
    dotenv::dotenv().ok();
    let api_key = env::var("ANTHROPIC_API_KEY").expect("ANTHROPIC_API_KEY must be set");
    let prompt = env::var("PROMPT").unwrap_or_else(|_| "Hello, Claud!".to_string());

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(NOTARY_HOST)
        .port(NOTARY_PORT)
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder().build().unwrap();

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    // Configure a new prover with the unique session id returned from notary client.
    let prover_config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await
        .unwrap();

    println!("Prover setup complete!");
    // Open a new socket to the application server.
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Grab a control handle to the Prover
    let prover_ctrl = prover_fut.control();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Prepare the JSON body for the OpenAI API request
    let json_body = json!({
        "model": "claude-3-5-sonnet-20240620",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": "Hello, world"}
        ]
    });


    debug!("Sending request to OpenAI API...");


    // Build the HTTP request to send the prompt to OpenAI API
    let request = Request::builder()
         .method(Method::POST)
        .uri("/v1/messages")
        .header("Host", SERVER_DOMAIN)
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header(CONTENT_TYPE, "application/json")
        .header("x-api-key", api_key.as_str())
        .header("anthropic-version", "2023-06-01")
        .body(json_body.to_string())
        .unwrap();

    println!("Request: {:?}", request);

    debug!("Sending request to OpenAI");

    // Defer decryption to speed up the proving process
    prover_ctrl.defer_decryption().await.unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request to OpenAI");

    println!("Response: {:?}", response);


    // Collect the body
    let payload = response.into_body().collect().await.unwrap().to_bytes();

    // Convert bytes to string
    let body_str = str::from_utf8(&payload).unwrap();

    // Print the response content
    println!("Response content: {}", body_str);

    // assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request to OpenAI succeeded");

    // Pretty printing the response
    // let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Upgrade the prover to an HTTP prover, and start notarization.
    let mut prover = prover.to_http().unwrap().start_notarize();

    // Commit to the transcript with the default committer, which will commit using BLAKE3.
    prover.commit().unwrap();

    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    // Dump the notarized session to a file
    let mut file = tokio::fs::File::create("claud_response.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(notarized_session.session())
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.session().data().build_substrings_proof();
    // Prove the request, revealing only the necessary headers.
    let request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();

    for header in &request.headers {
        // Only reveal the Host and Authorization headers
        if header.name.as_str().eq_ignore_ascii_case("Host") || header.name.as_str().eq_ignore_ascii_case("Authorization") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("claud_response_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();
}