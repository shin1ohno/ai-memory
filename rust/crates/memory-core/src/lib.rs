//! The memory store's core, independent of the MCP SDK and of any HTTP client.
//!
//! W1 declares only the two seams the rest of the core is written against: [`EsBackend`]
//! (Elasticsearch over its REST API) and [`Embedder`] (the embedding provider). W4a adds the
//! tool logic (recall, remember, ingest, ...) on top of them; tests and the round-trip suite's
//! fakes implement them in memory.
//!
//! Both traits work at the level the contracts are stated at: C-ES-2 freezes the method,
//! path, query and body sent to Elasticsearch, and C-EMB-1 the embedding request, so the seams
//! carry exactly those and no client library types.

#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;

use serde_json::Value;

/// An HTTP method Elasticsearch is called with (C-ES-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

/// The body of an Elasticsearch request.
#[derive(Clone, Debug, PartialEq)]
pub enum EsBody {
    None,
    Json(Value),
    /// `_bulk`: newline-delimited JSON, sent as `application/x-ndjson`, ending with a newline.
    NdJson(String),
}

/// One Elasticsearch call. `path` starts with `/` and carries no query string; `query` keeps
/// its order (`refresh=wait_for`, `retry_on_conflict=3`, `conflicts=proceed`, `if_seq_no`...).
#[derive(Clone, Debug, PartialEq)]
pub struct EsRequest {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: EsBody,
}

impl EsRequest {
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        EsRequest {
            method,
            path: path.into(),
            query: Vec::new(),
            body: EsBody::None,
        }
    }

    pub fn query(mut self, key: &str, value: &str) -> Self {
        self.query.push((key.to_owned(), value.to_owned()));
        self
    }

    pub fn json(mut self, body: Value) -> Self {
        self.body = EsBody::Json(body);
        self
    }

    pub fn ndjson(mut self, body: String) -> Self {
        self.body = EsBody::NdJson(body);
        self
    }
}

/// An Elasticsearch answer. Error statuses are answers too: callers branch on 400
/// `resource_already_exists_exception`, 403 on an existing index (C-ES-5), 404 and 409.
/// `body` is `Value::Null` for an empty body (HEAD).
#[derive(Clone, Debug, PartialEq)]
pub struct EsResponse {
    pub status: u16,
    pub body: Value,
}

impl EsResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The call did not produce an answer: connection, TLS, timeout, or a body that is not JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EsError {
    Transport(String),
    Decode(String),
}

impl fmt::Display for EsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EsError::Transport(m) => write!(f, "elasticsearch transport: {m}"),
            EsError::Decode(m) => write!(f, "elasticsearch response: {m}"),
        }
    }
}

impl std::error::Error for EsError {}

/// Elasticsearch as the core sees it: one REST call at a time, authenticated and addressed
/// by the implementation (base URL, `ES_USER`/`ES_PASSWORD`, `ES_VERIFY_CERTS`; C-OPS-2).
///
/// An implementation must not retry on its own: the core decides retries (startup's 10 x
/// 3 s, C-ES-5), and a hidden retry would change what C-ES-2 records.
pub trait EsBackend: Send + Sync {
    fn call(&self, request: EsRequest) -> impl Future<Output = Result<EsResponse, EsError>> + Send;
}

/// What an embedding is for (C-EMB-1: Voyage's `input_type`; the OpenAI-compatible shape
/// ignores it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputType {
    Query,
    Document,
}

impl InputType {
    pub fn as_str(self) -> &'static str {
        match self {
            InputType::Query => "query",
            InputType::Document => "document",
        }
    }
}

/// No embedding could be obtained: a 4xx, or a 5xx / transport failure after the one retry.
/// recall degrades to BM25 only on this error; write paths surface it as a tool error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbedError(pub String);

impl fmt::Display for EmbedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "embeddings unavailable: {}", self.0)
    }
}

impl std::error::Error for EmbedError {}

/// The embedding provider (C-EMB-1).
///
/// `embed_batch` sends one request for at most `contracts::embedding::BATCH_MAX` inputs and
/// returns one vector per input in input order (restored from the response's `index`), each
/// of [`Embedder::dimensions`] values. It applies the retry rule itself (one retry after
/// 500 ms on 5xx or transport failure, none on 4xx), because that rule is part of the
/// provider contract rather than of any caller. Splitting longer input lists into batches is
/// the caller's job, so every caller batches the same way.
pub trait Embedder: Send + Sync {
    fn dimensions(&self) -> usize;

    fn embed_batch(
        &self,
        inputs: &[String],
        input_type: InputType,
    ) -> impl Future<Output = Result<Vec<Vec<f32>>, EmbedError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The traits are implementable without any runtime crate: a recording fake, like the
    /// ones the core's own tests will use.
    struct Recorder(Mutex<Vec<EsRequest>>);

    impl EsBackend for Recorder {
        fn call(
            &self,
            request: EsRequest,
        ) -> impl Future<Output = Result<EsResponse, EsError>> + Send {
            self.0.lock().unwrap().push(request);
            std::future::ready(Ok(EsResponse {
                status: 200,
                body: serde_json::json!({"acknowledged": true}),
            }))
        }
    }

    struct Fixed;

    impl Embedder for Fixed {
        fn dimensions(&self) -> usize {
            3
        }

        fn embed_batch(
            &self,
            inputs: &[String],
            _input_type: InputType,
        ) -> impl Future<Output = Result<Vec<Vec<f32>>, EmbedError>> + Send {
            std::future::ready(Ok(inputs.iter().map(|_| vec![0.0, 0.0, 1.0]).collect()))
        }
    }

    /// Drive a future that is ready on first poll, without an async runtime.
    fn now<F: Future>(f: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        let mut f = pin!(f);
        match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("not ready"),
        }
    }

    #[test]
    fn es_backend_records_requests() {
        let es = Recorder(Mutex::new(Vec::new()));
        let req = EsRequest::new(Method::Post, "/memory-fact/_doc")
            .query("refresh", "wait_for")
            .json(serde_json::json!({}));
        let resp = now(es.call(req.clone())).unwrap();
        assert!(resp.is_success());
        assert_eq!(es.0.lock().unwrap().as_slice(), &[req]);
    }

    #[test]
    fn embedder_returns_one_vector_per_input() {
        let out = now(Fixed.embed_batch(&["a".into(), "b".into()], InputType::Document)).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|v| v.len() == Fixed.dimensions()));
        assert_eq!(InputType::Query.as_str(), "query");
    }
}
