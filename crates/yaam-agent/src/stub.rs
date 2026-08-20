//! A minimal HTTP/1.1 stub of the service, for tests only.
//!
//! Hand-rolled rather than borrowed from a framework so that a test can return any status it likes,
//! including the ones a well-behaved server would not, and so the status mapping is exercised
//! against real sockets rather than a mocked client.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A running stub service.
pub(crate) struct Stub {
    /// Base URL to configure an [`crate::upstream::Upstream`] with.
    pub(crate) base_url: String,
    /// Status the next request will get.
    status: Arc<AtomicU16>,
    /// Bodies received so far, in arrival order.
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Request heads received so far, so a test can check where a record was posted and what it
    /// was signed as.
    heads: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    /// Starts a stub on an ephemeral port, answering every request with `status` until told
    /// otherwise.
    pub(crate) async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let status = Arc::new(AtomicU16::new(status));
        let received = Arc::new(Mutex::new(Vec::new()));
        let heads = Arc::new(Mutex::new(Vec::new()));

        let task = (
            Arc::clone(&status),
            Arc::clone(&received),
            Arc::clone(&heads),
        );
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (status, received, heads) = (
                    Arc::clone(&task.0),
                    Arc::clone(&task.1),
                    Arc::clone(&task.2),
                );
                tokio::spawn(async move {
                    serve_one(stream, &status, &received, &heads).await;
                });
            }
        });

        Self {
            base_url,
            status,
            received,
            heads,
        }
    }

    /// Changes the status subsequent requests get.
    pub(crate) fn respond_with(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    /// Bodies received so far.
    pub(crate) fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }

    /// Request lines received so far, e.g. `POST /records HTTP/1.1`.
    pub(crate) fn request_lines(&self) -> Vec<String> {
        self.heads
            .lock()
            .unwrap()
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_owned())
            .collect()
    }

    /// Value of `name` on the request at `index`, lowercased header name.
    pub(crate) fn header(&self, index: usize, name: &str) -> Option<String> {
        let heads = self.heads.lock().unwrap();
        heads.get(index)?.lines().find_map(|line| {
            let (found, value) = line.split_once(':')?;
            found
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }
}

/// Reads one request, records its body, and answers with the configured status.
async fn serve_one(
    mut stream: TcpStream,
    status: &AtomicU16,
    received: &Mutex<Vec<Vec<u8>>>,
    heads: &Mutex<Vec<String>>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];

    // Read until the headers are complete, then until content-length bytes of body have arrived.
    let head_end = loop {
        if let Some(at) = find(&buf, b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let want = content_length(&buf[..head_end]);
    while buf.len() - head_end < want {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }

    heads
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&buf[..head_end]).into_owned());
    received
        .lock()
        .unwrap()
        .push(buf[head_end..head_end + want].to_vec());

    let code = status.load(Ordering::SeqCst);
    let body = format!("stub says {code}");
    let response = format!(
        "HTTP/1.1 {code} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Declared body length, or zero when the header is absent.
fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}
