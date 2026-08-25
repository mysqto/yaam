//! Asking a deployment what it remembers, over a caller's read socket.
//!
//! The read half of [`crate::emit`]. Writing one record became one command; reading had no command
//! at all, which left a signed request assembled by hand as the only way in — and a caller that
//! signs by hand is a caller holding a key.
//!
//! # Why no key, and no store
//!
//! The sidecar's read socket signs on the caller's behalf: an ordinary HTTP request goes in, the
//! sidecar adds the signature and forwards it, and the service's answer comes back untouched. So
//! there is nothing to configure here but the socket. No signing key, because a read tool holding
//! one is the thing the proxy exists to avoid; no `--root`, because a reader has no business opening
//! the tree; and no `--agent`, because the socket is the evidence of who is asking.
//!
//! # What comes out
//!
//! The service's bytes, on stdout, unchanged — not reformatted, not summarised, not unwrapped. The
//! caller is a program or a memory sub-agent, and an answer this rewrote would be parsed twice.
//!
//! # An empty answer is an answer
//!
//! The one distinction the exit codes exist to keep. A read that matched nothing is `200` with no
//! rows, and it exits [`Exit::Ok`]; a read the service refused exits [`Exit::Rejected`] and a read
//! that never reached it exits [`Exit::Unreachable`]. Collapsing the first into either of the others
//! would make every quiet day look like an outage.
//!
//! # Naming the entities a caller does not know it has
//!
//! A bundle composes context out of entities and an actor, which assumes the caller can name them.
//! A caller that has a *sentence* — the message it is about to answer — can name neither, so it asks
//! about the actor alone and gets whatever that actor happened to write. Where nothing was ever
//! written under that name, the answer is empty every time, and nothing about it looks broken.
//!
//! `--infer-entities` with `--infer-from` is the way out: the same extractor `yaam-emit` runs over a
//! record's prose, run here over the request's prose, and what comes out are lookup keys. See
//! [`terms`] for why that is allowed to guess where the writer is not.

use std::fmt::Display;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::cli::{ReadArgs, ReadQuery};
use crate::config::ReadSettings;
use crate::error::{Error, Result, failed};
use crate::exit::Exit;
use crate::infer;

/// How long to wait for an answer, in milliseconds.
///
/// The same figure the emitter uses, chosen for a different reason: nothing is flushed ahead of a
/// read, but the sidecar is waiting on the service, which is waiting on an index that may be
/// scanning thousands of full-text matches. A bound all the same — a hook that blocks for ever on a
/// wedged socket stops whatever called it.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// What a socket said, once its answer has been read.
struct Answer {
    /// The status the service reported, or the sidecar reported for it.
    status: u16,
    /// The body exactly as it arrived.
    body: Vec<u8>,
}

/// Builds one request, sends it, and prints what came back.
///
/// The request is assembled and checked before a socket is opened, so a query that cannot be
/// answered as asked fails here — naming the flag — rather than after a round trip that names a
/// query parameter the caller never typed.
pub fn read(
    settings: &ReadSettings,
    args: &ReadArgs,
    query: &ReadQuery,
    out: &mut dyn Write,
) -> Result<Exit> {
    let request = request(&target(query)?);

    // The exact bytes the socket would receive, which is what "the request it would make" means. It
    // needs no socket on purpose: the emitter's dry run originally demanded the one it would have
    // sent to, which defeated the only thing a dry run is for.
    if args.dry_run {
        out.write_all(request.as_bytes())
            .map_err(|error| failed("writing the request", &error))?;
        return Ok(Exit::Ok);
    }

    let socket = settings.socket.as_deref().ok_or_else(|| {
        crate::error::config(format!(
            "no read socket: pass --socket or set {}. It is the sidecar's read socket, at \
             <state-dir>/sockets/<agent>.read.sock by default",
            crate::config::ENV_READ_SOCKET
        ))
    })?;
    let answer = exchange(
        socket,
        request.as_bytes(),
        Duration::from_millis(args.timeout_ms),
    )?;
    report(&answer, out)
}

/// The request target one read asks for, query string and all.
///
/// Every value is percent-encoded here rather than at the socket, because the signature the sidecar
/// adds covers the target exactly as sent: an encoding decided in two places is a signature the
/// service cannot reproduce.
fn target(query: &ReadQuery) -> Result<String> {
    let mut params = Params::default();
    Ok(match query {
        ReadQuery::Records {
            action,
            outcome,
            agent,
            attr,
            from_ms,
            to_ms,
            limit,
        } => {
            // Half a window is a different question rather than a narrower one, so the service
            // refuses it. Refused here instead: the caller left out a flag, and that is worth
            // hearing without a round trip.
            if from_ms.is_some() != to_ms.is_some() {
                return Err(Error::Usage(
                    "a window needs both --from-ms and --to-ms; one bound alone asks a different \
                     question rather than a narrower one"
                        .to_owned(),
                ));
            }
            if let Some(spec) = attr {
                attr_filter(spec)?;
            }
            params.optional("action", action.as_deref());
            params.optional("outcome", outcome.map(crate::cli::OutcomeArg::as_stored));
            params.optional("agent", agent.as_deref());
            params.optional("attr", attr.as_deref());
            params.optional("from_ms", *from_ms);
            params.optional("to_ms", *to_ms);
            params.optional("limit", *limit);
            format!("/records{}", params.query())
        }
        ReadQuery::History {
            entity,
            min_confidence,
            limit,
            from_ms,
            to_ms,
        } => {
            // The same refusal the records query makes, for the same reason: the caller left out a
            // flag, and that is worth hearing without a round trip.
            if from_ms.is_some() != to_ms.is_some() {
                return Err(Error::Usage(
                    "a window needs both --from-ms and --to-ms; one bound alone asks a different \
                     question rather than a narrower one"
                        .to_owned(),
                ));
            }
            let (kind, id) = entity_term(entity)?;
            params.optional("min_confidence", *min_confidence);
            params.optional("limit", *limit);
            params.optional("from_ms", *from_ms);
            params.optional("to_ms", *to_ms);
            // Both segments encoded: several configured entity kinds carry `/`, `#` or `@` inside an
            // identifier, and those are the characters that decide where a path segment ends.
            format!(
                "/entities/{}/{}{}",
                encoded(kind),
                encoded(id),
                params.query()
            )
        }
        ReadQuery::Search { query, limit } => {
            params.add("q", query);
            params.optional("limit", *limit);
            format!("/search{}", params.query())
        }
        ReadQuery::Bundle {
            entities,
            actor,
            infer_entities,
            infer_from,
            deadline_ms,
            limit,
        } => {
            for spec in entities {
                bundle_term(spec)?;
            }
            let asked = terms(entities, infer_entities.as_deref(), infer_from.as_deref())?;
            if !asked.is_empty() {
                params.add("entity", &asked.join(","));
            }
            params.optional("actor", actor.as_deref());
            params.optional("deadline_ms", *deadline_ms);
            params.optional("limit", *limit);
            format!("/bundle{}", params.query())
        }
    })
}

/// The bytes one read puts on the socket.
///
/// Two headers, both load-bearing. `host` because HTTP/1.1 requires one and the proxy takes nothing
/// from it; `connection: close` because it is what makes end-of-file the end of the answer, so
/// nothing here has to agree with the sidecar about a content length.
fn request(target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
}

/// Sends one request and reads the whole answer.
///
/// Every transport failure here is [`Error::Unreachable`], and that is the difference from the
/// emitter. A record whose answer never arrived may or may not have been stored, so the emitter
/// refuses to guess; a read changes nothing, so an answer that did not arrive means exactly one
/// thing — nothing was read, and asking again is safe.
fn exchange(socket: &Path, request: &[u8], timeout: Duration) -> Result<Answer> {
    let stream = UnixStream::connect(socket).map_err(|error| {
        Error::Unreachable(format!(
            "{}: {error}. Nothing was read. The socket is bound by a sidecar serving this caller, \
             and it is the `.read.sock` rather than the record socket beside it",
            socket.display()
        ))
    })?;
    for set in [UnixStream::set_read_timeout, UnixStream::set_write_timeout] {
        set(&stream, Some(timeout)).map_err(|error| failed("bounding the socket wait", &error))?;
    }

    let mut writing = &stream;
    if let Err(error) = writing.write_all(request).and_then(|()| writing.flush()) {
        return Err(silence(socket, &error));
    }

    let raw = answer_bytes(&stream, socket)?;
    if raw.is_empty() {
        return Err(Error::Unreachable(format!(
            "{} closed without answering, so nothing was read. The read socket drops a connection \
             from another user without a word, so it has to belong to whoever runs this",
            socket.display()
        )));
    }
    parse(&raw, socket)
}

/// Reads until the socket hangs up, or until it has proved it is not answering HTTP.
///
/// The early exit is what makes the commonest mistake instant instead of slow. Handed an HTTP
/// request, the *record* socket answers one rejection per line and then waits for more records — so
/// end-of-file never comes, and a plain read to the end would sit out the whole timeout before
/// reporting something that was decided by the first line.
fn answer_bytes(stream: &UnixStream, socket: &Path) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut judged = false;
    loop {
        let read = (&*stream)
            .read(&mut chunk)
            .map_err(|error| silence(socket, &error))?;
        if read == 0 {
            return Ok(raw);
        }
        raw.extend_from_slice(&chunk[..read]);
        // Judged once a whole first line is in hand, and only then: a status line can arrive in two
        // reads, and half of one is not evidence of anything.
        if !judged && raw.contains(&b'\n') {
            judged = true;
            if !answers_http(&raw) {
                return Err(unreadable(&raw, socket, "it does not begin with a status"));
            }
        }
    }
}

/// Whether what came back is an HTTP/1 answer at all.
///
/// One predicate for the early exit and for the parse, so the two cannot come to different
/// conclusions about the same bytes.
fn answers_http(raw: &[u8]) -> bool {
    raw.starts_with(b"HTTP/1.")
}

/// What an exchange that produced no usable answer means.
///
/// One outcome, unlike the emitter's two: nothing was read either way, so a wait that ran out and a
/// connection that was reset call for the same thing, which is asking again.
fn silence(socket: &Path, error: &std::io::Error) -> Error {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        return Error::Unreachable(format!(
            "no answer from {} in time ({error}). Nothing was read, and a read changes nothing, so \
             asking again is safe",
            socket.display()
        ));
    }
    Error::Unreachable(format!(
        "{} stopped answering ({error}), so nothing was read",
        socket.display()
    ))
}

/// Reads the status and body out of one HTTP/1.1 answer.
///
/// Strict about the framing on purpose. What answers this socket is the sidecar's own proxy, which
/// sends a whole response with its length known, so anything else on this socket is not the answer
/// this asked for — and the likeliest reason is the commonest mistake, which the guidance names.
fn parse(raw: &[u8], socket: &Path) -> Result<Answer> {
    if !answers_http(raw) {
        return Err(unreadable(raw, socket, "it does not begin with a status"));
    }
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| unreadable(raw, socket, "it carries no end of headers"))?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| unreadable(raw, socket, "its headers are not text"))?;
    let status: u16 = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| unreadable(raw, socket, "its status is not a number"))?;
    // A chunked body would need de-framing, and the proxy never sends one: it answers with a body
    // whose length it already knows. Refused rather than handed on, because handing on the frames
    // would print bytes that are not the answer.
    if head
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:"))
    {
        return Err(unreadable(raw, socket, "its body is not framed by length"));
    }

    Ok(Answer {
        status,
        body: raw[split + 4..].to_vec(),
    })
}

/// An answer this cannot read, and the mistake that usually produced it.
///
/// The record socket is the guess worth making. Both sockets sit in one directory under names one
/// character apart, and a record socket handed an HTTP request answers a rejected record — which is
/// JSON, so it looks almost right.
fn unreadable(raw: &[u8], socket: &Path, why: &str) -> Error {
    let said = String::from_utf8_lossy(&raw[..raw.len().min(200)])
        .trim()
        .to_owned();
    let hint = if said.contains("\"status\"") {
        ". That is the record socket answering a malformed record: the read socket is the \
         `.read.sock` beside it"
    } else {
        ""
    };
    Error::Failed(format!(
        "{} did not answer HTTP — {why}: {said}{hint}",
        socket.display()
    ))
}

/// Turns one answer into what a script branches on, and prints the body when there is one to print.
///
/// The three outcomes the codes exist to separate, plus the catch-all. An empty page is an answer
/// and exits zero. A refusal names the request the caller has to fix. `503` is the service being
/// unreachable from the sidecar — reads are never queued, so it is the same outcome as a socket that
/// did not answer, and a script retries both the same way.
fn report(answer: &Answer, out: &mut dyn Write) -> Result<Exit> {
    let said = String::from_utf8_lossy(&answer.body).trim().to_owned();
    match answer.status {
        // Written byte for byte, including the absence of a trailing newline: the caller asked for
        // the service's answer, and a byte this added is a byte it has to strip.
        200..=299 => {
            out.write_all(&answer.body)
                .map_err(|error| failed("writing the answer", &error))?;
            Ok(Exit::Ok)
        }
        // Not the request's fault and not fixable by rewriting it: what the sidecar signs as is
        // decided by the deployment's keyring, which the caller does not hold.
        401 | 403 => Err(Error::Failed(format!(
            "the service would not authenticate this read ({}): {said}. The sidecar signs it, so \
             what needs fixing is the deployment's keyring rather than the request",
            answer.status
        ))),
        503 => Err(Error::Unreachable(format!(
            "the service could not answer ({said}), so nothing was read. A read is never queued — \
             an answer that arrived later would be data that was already stale"
        ))),
        400..=499 => Err(Error::Rejected(match answer.status {
            // The one refusal that is not the `{"error": …}` shape: an unknown or unparseable query
            // parameter is refused before a handler runs, and refused rather than ignored, because a
            // dropped filter widens the question to everything.
            400 => format!(
                "the service refused this request (400): {said}. A parameter it does not know is \
                 refused rather than ignored"
            ),
            other => format!("the service refused this request ({other}): {said}"),
        })),
        other => Err(Error::Failed(format!(
            "the service answered {other}, which no read should be answered with: {said}"
        ))),
    }
}

/// One query string, built from the flags that were actually given.
#[derive(Default)]
struct Params(Vec<String>);

impl Params {
    /// Adds one parameter, percent-encoding its value.
    fn add(&mut self, name: &str, value: &str) {
        self.0.push(format!("{name}={}", encoded(value)));
    }

    /// Adds one parameter if the caller named it, and otherwise sends nothing.
    ///
    /// Absent is not the same as defaulted. Every optional parameter here has a documented default
    /// at the service, and filling one in from this build would be a second place for that figure to
    /// live — out of date the first time the service changed its mind.
    fn optional(&mut self, name: &str, value: Option<impl Display>) {
        if let Some(value) = value {
            self.add(name, &value.to_string());
        }
    }

    /// The query string, empty when nothing was given.
    fn query(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            format!("?{}", self.0.join("&"))
        }
    }
}

/// Percent-encodes one value for a path segment or a query parameter.
///
/// Everything outside the unreserved set, which is stricter than either position needs and is what
/// makes one function right for both. It is also what keeps a request line a request line: a value
/// carrying a space, a newline or a `?` cannot reshape the target it is a value in.
fn encoded(value: &str) -> String {
    /// Upper-case hex, because a percent-escape is conventionally upper-case.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

/// Checks one `key=value` attribute filter.
///
/// The service refuses one that is not a pair, so this refuses it first. Split at the first `=`,
/// because a value may contain one and a declared attribute key may not — the same rule the emitter
/// reads its `--attr` under, so a filter can be spelled the way the record was written.
fn attr_filter(spec: &str) -> Result<()> {
    match spec.split_once('=') {
        Some((key, _)) if !key.is_empty() => Ok(()),
        _ => Err(Error::Usage(format!(
            "--attr {spec} is not `key=value`; it filters on a declared attribute the record \
             carries in plaintext"
        ))),
    }
}

/// Splits one `kind:id` entity term.
///
/// At the first `:`, as the emitter's `--entity` does: a kind cannot contain one and an identifier
/// can.
fn entity_term(spec: &str) -> Result<(&str, &str)> {
    let (kind, id) = spec.split_once(':').ok_or_else(|| {
        Error::Usage(format!(
            "--entity {spec} is not `kind:id`; the kind is one the deployment declares in \
             spec/entities.yaml"
        ))
    })?;
    if kind.is_empty() || id.is_empty() {
        return Err(Error::Usage(format!(
            "--entity {spec} needs both a kind and an identifier"
        )));
    }
    Ok((kind, id))
}

/// How many inferred terms one bundle may carry, beyond what the caller stated.
///
/// Generous for a question a person wrote and firm against prose that is really a data file. There
/// is no right number; there is only a number, and an unbounded query parameter is worse than any
/// of them.
const MAX_INFERRED_TERMS: usize = 32;

/// Every entity a bundle asks about: what the caller stated, then what its prose supports.
///
/// # Why this may guess where the writer may not
///
/// The extractor is the same one `yaam-emit --infer-entities` runs, and the bar it enforces was set
/// for the write path: an inferred reference *becomes* a stored join key there, so it is kept below
/// [`yaam_contract::extract::HIGH_CONFIDENCE_FLOOR`], and a bundle in turn gathers only references a
/// record states at `1.0` — because a guess in a bundle is a guess the caller cannot tell apart from
/// a fact.
///
/// None of that changes here, and none of it applies to this. What comes out of the extractor here
/// never reaches a record and never reaches an answer: it is a `kind:id` in a query parameter, and
/// the service matches it against references records state at full confidence, exactly as it matches
/// one the caller typed. So a wrong guess asks about an entity nobody wrote anything under and gets
/// nothing back, at the price of one lookup. A wrong guess at write time is permanent and silent.
///
/// The asymmetry is the whole reason this exists: inference cheap enough to be worth doing is
/// inference on the read side, and the floor the write side holds is untouched by it.
///
/// Which is why this calls [`yaam_contract::extract::Extractor::from_query`] and not `from_text`.
/// The anchor a rule requires is evidence for a *stored* reference; requiring it of a lookup key
/// asks a question to justify itself, and the questions people actually type do not. `any knowledge
/// about this? WUPGHGJ7ELJM626` reached anchored extraction as prose about nothing.
///
/// # One flag alone
///
/// Refused, both ways round. Text with no rules cannot be read and rules with no text have nothing
/// to read, and either would compose a *narrower* bundle than the caller asked for while answering
/// `200` — which is the one failure this whole file is arranged to make impossible.
fn terms(stated: &[String], spec_dir: Option<&Path>, text: Option<&str>) -> Result<Vec<String>> {
    let (Some(dir), Some(text)) = (spec_dir, text) else {
        if spec_dir.is_some() || text.is_some() {
            return Err(Error::Usage(
                "inference needs both --infer-entities and --infer-from: one names the rules, the \
                 other the prose to read with them, and neither does anything alone"
                    .to_owned(),
            ));
        }
        return Ok(stated.to_vec());
    };

    let extractor = infer::load(dir)?;
    // Canonical on both sides, as the emitter compares them: the service canonicalises what it is
    // given, so `deploy:svc/prod#7` stated and the same inferred are one key by the time it matches.
    let claimed: Vec<String> = stated
        .iter()
        .filter_map(|spec| spec.split_once(':'))
        .map(|(kind, id)| {
            let id = extractor
                .registry()
                .canonicalise(kind, id)
                .unwrap_or_else(|_| id.to_owned());
            format!("{kind}:{id}")
        })
        .collect();

    let mut asked = stated.to_vec();
    asked.extend(
        extractor
            .from_query(text)
            // The extractor deduplicates its own findings, so only the stated ones are left to check.
            .into_iter()
            .map(|found| format!("{}:{}", found.kind, found.id))
            // A comma is how a bundle separates its terms, so one inside an identifier would arrive
            // as two. A stated term carrying one is refused by name; an inferred one is dropped,
            // because a guess is not worth failing a caller's read over.
            .filter(|term| !term.contains(',') && !claimed.contains(term))
            // Bounded, because unanchored inference is bounded only by the prose: a state dump
            // pasted into a question yielded fifteen hundred candidates in testing, and a query
            // parameter that long is a request the service rejects rather than answers. Stated
            // terms are never dropped -- only guesses are, and only after the cap is reached.
            .take(MAX_INFERRED_TERMS),
    );
    Ok(asked)
}

/// Checks one entity term a bundle will carry.
///
/// A bundle takes its entities as one comma-separated parameter, so a term holding a comma would
/// arrive as two the service could not make sense of. Refused here, where it can still be named: the
/// service would see two malformed terms and report on those instead.
fn bundle_term(spec: &str) -> Result<()> {
    entity_term(spec)?;
    if spec.contains(',') {
        return Err(Error::Usage(format!(
            "--entity {spec} holds a comma, which is how a bundle separates its entities. Ask for \
             this one on its own with `yaam-read history`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use clap::Parser;

    use super::{MAX_INFERRED_TERMS, Params, encoded, read, target};
    use crate::cli::{OutcomeArg, ReadCli};
    use crate::config::{Env, ReadSettings};
    use crate::error::Error;
    use crate::exit::Exit;

    /// The command line a caller would type, parsed.
    fn parsed(args: &[&str]) -> ReadCli {
        let mut all = vec!["yaam-read"];
        all.extend_from_slice(args);
        ReadCli::try_parse_from(all).expect("parsed")
    }

    fn settings(socket: PathBuf) -> ReadSettings {
        ReadSettings {
            socket: Some(socket),
        }
    }

    /// The target one command line asks for.
    fn asked(args: &[&str]) -> String {
        target(&parsed(args).query).expect("a target")
    }

    /// A socket that answers one raw HTTP response, whatever was asked.
    ///
    /// The request is read before anything is answered, so a caller that never managed to send one
    /// cannot pass by being answered anyway. The request line is handed back for assertion.
    fn answering(
        dir: &std::path::Path,
        name: &str,
        answer: String,
    ) -> (PathBuf, std::sync::mpsc::Receiver<String>) {
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).expect("bind");
        let (sending, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut line)
                .expect("the request line");
            sending.send(line).expect("report the request");
            let _ = stream.write_all(answer.as_bytes());
        });
        (path, received)
    }

    /// One answer wrapped in the framing the sidecar's proxy uses.
    fn framed(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// Every read the service answers is reachable, and each becomes the target the spec documents.
    #[test]
    fn each_read_becomes_the_request_the_service_documents() {
        assert_eq!(
            asked(&[
                "records",
                "--action",
                "deploy",
                "--outcome",
                "success",
                "--agent",
                "agent_a",
                "--limit",
                "5"
            ]),
            "/records?action=deploy&outcome=success&agent=agent_a&limit=5"
        );
        assert_eq!(
            asked(&["search", "--query", "rolled back", "--limit", "3"]),
            "/search?q=rolled%20back&limit=3"
        );
        assert_eq!(
            asked(&["history", "--entity", "ticket:PROJ-42"]),
            "/entities/ticket/PROJ-42"
        );
        assert_eq!(
            asked(&[
                "bundle",
                "--entity",
                "ticket:PROJ-42",
                "--entity",
                "deploy:api",
                "--actor",
                "agent_a",
                "--limit",
                "5"
            ]),
            "/bundle?entity=ticket%3APROJ-42%2Cdeploy%3Aapi&actor=agent_a&limit=5"
        );
    }

    /// A flag the caller did not name is not sent, because the service's own default is the one
    /// figure that should decide it.
    #[test]
    fn nothing_the_caller_did_not_ask_for_is_sent() {
        assert_eq!(asked(&["records"]), "/records");
        assert_eq!(asked(&["bundle"]), "/bundle");
        assert_eq!(
            asked(&["history", "--entity", "ticket:PROJ-42"]).find('?'),
            None
        );
    }

    /// An identifier carrying the characters that end a path segment still names one entity.
    #[test]
    fn an_entity_identifier_is_encoded_rather_than_broken_into_segments() {
        assert_eq!(
            asked(&["history", "--entity", "deploy:api/staging#1146"]),
            "/entities/deploy/api%2Fstaging%231146"
        );
        // The kind is split off at the first colon, so the identifier keeps its own.
        assert_eq!(
            asked(&["history", "--entity", "chat_user:x:y"]),
            "/entities/chat_user/x%3Ay"
        );
    }

    /// The rules the workspace ships, as a caller names them.
    fn spec_dir() -> String {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec")
            .to_str()
            .expect("utf-8 path")
            .to_owned()
    }

    /// One bundle over prose, with the shipped rules to read it by.
    fn about(text: &str, extra: &[&str]) -> String {
        let spec = spec_dir();
        let mut args = vec!["bundle", "--infer-entities", &spec, "--infer-from", text];
        args.extend_from_slice(extra);
        asked(&args)
    }

    /// Prose the rules anchor becomes a key the bundle looks up, which is the whole point: a caller
    /// holding a sentence can now name entities it never knew it had.
    #[test]
    fn prose_the_rules_anchor_becomes_an_entity_the_bundle_asks_about() {
        assert_eq!(
            about("reopened ticket PROJ-42 this morning", &[]),
            "/bundle?entity=ticket%3APROJ-42"
        );
        // Several kinds out of one sentence, in the order the prose names them.
        assert_eq!(
            about(
                "replying in thread C0EXAMPLE/1700000000.000100 about ticket PROJ-42",
                &["--actor", "agent_a"]
            ),
            "/bundle?entity=chat_thread%3AC0EXAMPLE%2F1700000000.000100%2Cticket%3APROJ-42\
             &actor=agent_a"
        );
    }

    /// The question that made `from_query` necessary: a bare identifier, nothing vouching for it.
    #[test]
    fn a_bare_identifier_in_a_question_becomes_a_key() {
        assert_eq!(
            about("any knowledge abou this? PROJ-42", &[]),
            "/bundle?entity=ticket%3APROJ-42"
        );
        // And with no prose around it at all, which is how people paste a reference.
        assert_eq!(about("PROJ-42", &[]), "/bundle?entity=ticket%3APROJ-42");
    }

    /// Guesses are capped; stated terms are not.
    ///
    /// The prose here is what a pasted data file looks like to the reader, and the point of the cap
    /// is that the request stays a request.
    #[test]
    fn inferred_terms_are_capped_and_stated_ones_survive_the_cap() {
        let flood = (0..MAX_INFERRED_TERMS * 2)
            .map(|n| format!("PROJ-{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let url = about(&flood, &["--entity", "ticket:KEPT-1"]);
        let terms = url.matches("ticket%3A").count();
        assert_eq!(
            terms,
            MAX_INFERRED_TERMS + 1,
            "the cap, plus the stated one: {url}"
        );
        assert!(
            url.contains("ticket%3AKEPT-1"),
            "a stated term is never dropped: {url}"
        );
    }

    /// Prose that anchors nothing asks exactly what the same bundle asked before the flags existed.
    ///
    /// The default path is what almost every caller is on, so "adds nothing" has to mean the bytes
    /// rather than the intent — a request that merely *looked* the same would still be a request.
    #[test]
    fn prose_that_names_nothing_asks_byte_for_byte_what_it_asked_before() {
        let unchanged = asked(&["bundle", "--actor", "agent_a", "--limit", "5"]);
        assert_eq!(
            about(
                "let me know how that went when you get a chance",
                &["--actor", "agent_a", "--limit", "5"]
            ),
            unchanged
        );
        assert_eq!(unchanged, "/bundle?actor=agent_a&limit=5");
    }

    /// A stated entity the prose repeats travels once. Twice would charge the service two source
    /// reads for one key, and a bundle's cap is spent on the second one either way.
    #[test]
    fn an_entity_both_stated_and_inferred_is_asked_about_once() {
        assert_eq!(
            about("reopened ticket proj-42", &["--entity", "ticket:PROJ-42"]),
            "/bundle?entity=ticket%3APROJ-42"
        );
    }

    /// Either inference flag alone is refused rather than ignored.
    ///
    /// Ignoring one would compose a narrower bundle than the caller asked for and answer `200` — the
    /// shape of failure this file exists to prevent.
    #[test]
    fn either_inference_flag_without_the_other_is_a_usage_error() {
        let spec = spec_dir();
        for half in [
            vec!["bundle", "--infer-entities", &spec],
            vec!["bundle", "--infer-from", "reopened ticket PROJ-42"],
        ] {
            let error = target(&parsed(&half).query).expect_err("half of the pair");
            assert!(matches!(error, Error::Usage(_)), "{error}");
            assert!(error.to_string().contains("--infer-from"), "{error}");
        }
    }

    /// A spec directory that cannot be used stops the read, and says which file.
    ///
    /// A configuration fault rather than a usage one: the flags parsed, and what is wrong is on
    /// disk. Failing quietly would hand back a bundle missing exactly the entities that were asked
    /// for by inference.
    #[test]
    fn a_spec_directory_that_cannot_be_used_stops_the_read() {
        let dir = tempfile::tempdir().expect("temp dir");
        let empty = dir.path().to_str().expect("utf-8");
        let error = target(
            &parsed(&[
                "bundle",
                "--infer-entities",
                empty,
                "--infer-from",
                "reopened ticket PROJ-42",
            ])
            .query,
        )
        .expect_err("no entities.yaml");
        assert_eq!(error.exit(), Exit::Config, "{error}");
        assert!(error.to_string().contains("entities.yaml"), "{error}");
    }

    /// The attribute filter is spelled as the record was written, and reaches the service intact.
    #[test]
    fn an_attribute_filter_travels_as_one_value() {
        assert_eq!(
            asked(&["records", "--attr", "environment=staging"]),
            "/records?attr=environment%3Dstaging"
        );
    }

    /// A window is both bounds or neither, refused before a socket is opened.
    #[test]
    fn half_a_window_is_a_usage_error_rather_than_a_round_trip() {
        for half in [
            vec!["records", "--from-ms", "1755676800000"],
            vec!["records", "--to-ms", "1755763200000"],
        ] {
            let error = target(&parsed(&half).query).expect_err("half a window");
            assert!(matches!(error, Error::Usage(_)), "{error}");
            assert!(error.to_string().contains("--to-ms"), "{error}");
        }
        assert_eq!(
            asked(&[
                "records",
                "--from-ms",
                "1755676800000",
                "--to-ms",
                "1755763200000"
            ]),
            "/records?from_ms=1755676800000&to_ms=1755763200000"
        );
    }

    /// Each malformed argument is refused here, naming the flag, rather than over the socket.
    #[test]
    fn a_malformed_argument_is_a_usage_error_before_anything_is_sent() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["records", "--attr", "nokey"],
            vec!["records", "--attr", "=value"],
            vec!["history", "--entity", "nocolon"],
            vec!["history", "--entity", "ticket:"],
            vec!["history", "--entity", ":PROJ-42"],
            vec!["bundle", "--entity", "nocolon"],
            // A comma is how a bundle separates its terms, so one inside a term cannot travel.
            vec!["bundle", "--entity", "ticket:PROJ-42,PROJ-43"],
        ];
        for args in cases {
            let error = target(&parsed(&args).query).expect_err("refused");
            assert!(matches!(error, Error::Usage(_)), "{args:?} gave {error}");
            assert_eq!(error.exit(), Exit::Usage);
        }
    }

    /// The outcome a query filters on has to be spelled the way a stored record spells it: the
    /// service compares it against an indexed column, so a misspelling answers `200` and no rows.
    #[test]
    fn an_outcome_filter_carries_the_spelling_a_record_is_stored_with() {
        for outcome in [
            OutcomeArg::Success,
            OutcomeArg::Failure,
            OutcomeArg::Partial,
            OutcomeArg::Declined,
        ] {
            let stored = serde_json::to_string(&outcome.into_contract()).expect("serialised");
            assert_eq!(
                format!("\"{}\"", outcome.as_stored()),
                stored,
                "the flag and the record disagree about how to spell an outcome"
            );
        }
    }

    /// The dry run prints the request and needs no socket, which is the whole point of having one.
    #[test]
    fn a_dry_run_needs_no_socket_and_prints_a_sendable_request() {
        let cli = parsed(&["--dry-run", "records", "--action", "deploy"]);
        let resolved = ReadSettings::resolve(&cli.args, &Env::default());
        assert!(resolved.socket.is_none(), "a dry run needs no socket");

        let mut out = Vec::new();
        assert_eq!(
            read(&resolved, &cli.args, &cli.query, &mut out).expect("printed"),
            Exit::Ok
        );
        let printed = String::from_utf8(out).expect("utf-8");
        assert!(
            printed.starts_with("GET /records?action=deploy HTTP/1.1\r\n"),
            "{printed}"
        );
        // A whole request, so it can be piped into the socket by hand — the first thing anyone
        // integrating this tries.
        assert!(printed.ends_with("\r\n\r\n"), "{printed}");
        assert!(printed.to_lowercase().contains("host:"), "{printed}");
    }

    /// An answer with no rows is an answer: it prints, and it exits zero.
    #[test]
    fn a_read_that_matched_nothing_is_a_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = r#"{"records":[],"token_estimate":0}"#;
        let (path, requested) = answering(dir.path(), "read.sock", framed("200 OK", empty));

        let cli = parsed(&["records", "--action", "nothing-did-this"]);
        let mut out = Vec::new();
        let exit = read(&settings(path), &cli.args, &cli.query, &mut out).expect("answered");
        assert_eq!(exit, Exit::Ok, "an empty page is not an outage");
        assert_eq!(String::from_utf8(out).expect("utf-8"), empty);
        assert_eq!(
            requested.recv().expect("the request line").trim(),
            "GET /records?action=nothing-did-this HTTP/1.1"
        );
    }

    /// The service's bytes reach stdout unchanged, because a caller that has to reformat them has to
    /// parse them twice.
    #[test]
    fn the_answer_is_printed_exactly_as_it_arrived() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = "{\"records\":[{\"record_id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\"}],\n\
                    \"token_estimate\":7}";
        let (path, _requested) = answering(dir.path(), "read.sock", framed("200 OK", body));

        let cli = parsed(&["records"]);
        let mut out = Vec::new();
        read(&settings(path), &cli.args, &cli.query, &mut out).expect("answered");
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            body,
            "not reformatted, not re-indented, and no newline added"
        );
    }

    /// Each status the service can answer with becomes the code a script branches on.
    #[test]
    fn every_status_becomes_its_own_exit_code() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cases: [(&str, Exit); 7] = [
            ("200 OK", Exit::Ok),
            ("400 Bad Request", Exit::Rejected),
            ("422 Unprocessable Entity", Exit::Rejected),
            ("401 Unauthorized", Exit::Failed),
            ("500 Internal Server Error", Exit::Failed),
            ("503 Service Unavailable", Exit::Unreachable),
            ("302 Found", Exit::Failed),
        ];
        for (index, (status, expected)) in cases.into_iter().enumerate() {
            let answer = framed(status, r#"{"error":"said so"}"#);
            let (path, _requested) = answering(dir.path(), &format!("read-{index}.sock"), answer);
            let cli = parsed(&["records"]);
            let mut out = Vec::new();
            match read(&settings(path), &cli.args, &cli.query, &mut out) {
                Ok(exit) => assert_eq!(exit, expected, "{status}"),
                Err(error) => {
                    assert_eq!(error.exit(), expected, "{status}: {error}");
                    // The service's own reason, not a code the caller has to look up.
                    assert!(error.to_string().contains("said so"), "{error}");
                    assert!(out.is_empty(), "a refusal must not print an answer");
                }
            }
        }
    }

    /// A socket nothing is listening on says nothing was read, which is what tells the caller to
    /// retry rather than to fix its query.
    #[test]
    fn a_socket_nothing_is_listening_on_is_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cli = parsed(&["records"]);
        let mut out = Vec::new();
        let error = read(
            &settings(dir.path().join("absent.read.sock")),
            &cli.args,
            &cli.query,
            &mut out,
        )
        .expect_err("nothing is listening");
        assert_eq!(error.exit(), Exit::Unreachable);
        assert!(error.to_string().contains("Nothing was read"), "{error}");
        assert!(out.is_empty());
    }

    /// A connection dropped without a word is what a socket belonging to another user looks like.
    #[test]
    fn a_socket_that_closes_without_answering_is_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("silent.read.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || drop(listener.accept()));

        let cli = parsed(&["records"]);
        let mut out = Vec::new();
        let error = read(&settings(path), &cli.args, &cli.query, &mut out).expect_err("no answer");
        assert_eq!(error.exit(), Exit::Unreachable);
    }

    /// A wait that runs out is still "nothing was read": a read changes nothing, so unlike a record
    /// there is no ambiguity to preserve.
    #[test]
    fn a_silent_socket_times_out_and_says_asking_again_is_safe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mute.read.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let held = std::thread::spawn(move || {
            let accepted = listener.accept().expect("accept");
            std::thread::sleep(std::time::Duration::from_millis(500));
            drop(accepted);
        });

        let cli = parsed(&["--timeout-ms", "150", "records"]);
        let mut out = Vec::new();
        let error = read(&settings(path), &cli.args, &cli.query, &mut out).expect_err("timed out");
        assert_eq!(error.exit(), Exit::Unreachable);
        assert!(
            error.to_string().contains("asking again is safe"),
            "{error}"
        );
        held.join().expect("the holder");
    }

    /// Pointed at the record socket by mistake, it says so: the two sit in one directory under names
    /// one character apart, and the record socket's refusal is JSON, so it looks almost right.
    #[test]
    fn the_record_socket_is_named_when_it_answers_instead() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _requested) = answering(
            dir.path(),
            "agent_a.sock",
            "{\"status\":\"rejected\",\"reason\":\"expected value at line 1\"}\n".to_owned(),
        );

        let cli = parsed(&["records"]);
        let mut out = Vec::new();
        let error = read(&settings(path), &cli.args, &cli.query, &mut out).expect_err("not HTTP");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains(".read.sock"), "{error}");
    }

    /// A body this cannot frame is refused rather than printed, because printing the frames would
    /// print bytes that are not the answer.
    #[test]
    fn an_answer_this_cannot_frame_is_refused_rather_than_printed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _requested) = answering(
            dir.path(),
            "chunked.read.sock",
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                .to_owned(),
        );

        let cli = parsed(&["records"]);
        let mut out = Vec::new();
        let error = read(&settings(path), &cli.args, &cli.query, &mut out).expect_err("chunked");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    }

    /// The socket is refused at the send rather than at the resolve, and the refusal names the
    /// variable that would have supplied it.
    #[test]
    fn a_socket_is_required_and_can_come_from_the_environment() {
        let cli = parsed(&["records"]);
        let resolved = ReadSettings::resolve(&cli.args, &Env::default());
        assert!(resolved.socket.is_none());
        let mut sink = Vec::new();
        let missing =
            read(&resolved, &cli.args, &cli.query, &mut sink).expect_err("nothing names a socket");
        assert_eq!(missing.exit(), Exit::Config);
        assert!(
            missing.to_string().contains("YAAM_READ_SOCKET"),
            "{missing}"
        );

        let from_env = ReadSettings::resolve(
            &cli.args,
            &Env {
                read_socket: Some("/run/a.read.sock".into()),
                ..Env::default()
            },
        );
        assert_eq!(from_env.socket, Some(PathBuf::from("/run/a.read.sock")));

        // An empty variable is not a setting, here as everywhere else.
        let blank = ReadSettings::resolve(
            &cli.args,
            &Env {
                read_socket: Some(std::ffi::OsString::new()),
                ..Env::default()
            },
        );
        assert!(blank.socket.is_none());

        // And a flag beats the variable, in the one order this workspace uses everywhere.
        let flagged = parsed(&["--socket", "/run/b.read.sock", "records"]);
        let resolved = ReadSettings::resolve(
            &flagged.args,
            &Env {
                read_socket: Some("/run/a.read.sock".into()),
                ..Env::default()
            },
        );
        assert_eq!(resolved.socket, Some(PathBuf::from("/run/b.read.sock")));
    }

    /// Where the flags sit around the subcommand is not something a caller should have to remember.
    #[test]
    fn the_shared_flags_are_accepted_on_either_side_of_the_read() {
        for args in [
            vec!["--socket", "/run/a.read.sock", "--dry-run", "records"],
            vec!["records", "--socket", "/run/a.read.sock", "--dry-run"],
        ] {
            let cli = parsed(&args);
            assert!(cli.args.dry_run, "{args:?}");
            assert_eq!(cli.args.socket, Some(PathBuf::from("/run/a.read.sock")));
        }
    }

    /// Everything outside the unreserved set, so no value can reshape the target it sits in.
    #[test]
    fn encoding_covers_everything_that_could_reshape_a_request() {
        assert_eq!(encoded("aZ0-._~"), "aZ0-._~");
        assert_eq!(encoded("a b&c=d?e#f/g%h"), "a%20b%26c%3Dd%3Fe%23f%2Fg%25h");
        assert_eq!(
            encoded("GET /x HTTP/1.1\r\n"),
            "GET%20%2Fx%20HTTP%2F1.1%0D%0A",
            "a value must not be able to write a second request line"
        );
        // Not ASCII, so encoded per byte of its UTF-8 spelling.
        assert_eq!(encoded("é"), "%C3%A9");
    }

    #[test]
    fn a_query_string_is_empty_when_nothing_was_given() {
        let mut params = Params::default();
        assert_eq!(params.query(), "");
        params.optional("limit", None::<u32>);
        assert_eq!(params.query(), "");
        params.optional("limit", Some(5));
        assert_eq!(params.query(), "?limit=5");
    }
}
