//! Writing one record to a caller socket.
//!
//! The piece that makes everything else reachable. A record has seventeen required fields, and until
//! this existed the only way to write one was to build all seventeen as JSON by hand — which is why
//! nothing emitted records. Sixteen of them are either mechanical or a deployment-wide constant; one
//! shell hook's worth of argument is what is actually left to say.
//!
//! # What is filled in, and what is asked for
//!
//! Minted here: the identifier, both timestamps, the schema version, and every empty collection.
//! Asked for: the agent, what was done, how it went, the prose, and whatever attributes, entity
//! references and tags the caller has. Fixed: `subjects` is empty and `data_class` is
//! [`DataClass::Internal`] — see [`crate::cli::EmitCli`] for why there is no flag.
//!
//! # The timestamps, and why one flag is not enough
//!
//! Both default to now, which is what a hook firing beside the action means. `--at` moves the
//! instant the action happened to; `--backfilled` says the record was read out of a source rather
//! than observed, and makes `--at` the received time as well. The store orders, windows and joins on
//! the received time and treats the source-reported one as display, so the second flag is what
//! decides where a record lands: without it a note from three years ago sorts among today's, and the
//! windowed queries the history was imported for would answer as if none of it existed. Neither
//! shape is inferrable from the other — see [`stamps`] for the three refusals that follow.
//!
//! # Why the sidecar and not the service
//!
//! The sidecar seals, signs and spools. A caller posting to the service would need the service's own
//! signing key — the thing the sidecar exists so that callers never hold — and would have no spool,
//! so a record written while the service was restarting would simply be gone. So this opens no store
//! and no network connection: one unix socket, one JSON line out, one JSON line back.
//!
//! # Why the answer is read
//!
//! Because it is the acknowledgement. Three of the five things the sidecar can say mean the record is
//! not stored, and two of those are permanent. A caller that wrote the line and walked away would be
//! claiming a durability nothing gave it, so the exchange here always waits for the answer and always
//! turns it into an exit code — including the one that says "stored, just not there yet".

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yaam_agent::listener::{Answer, Status};
use yaam_contract::entity::{self, EntityRef};
use yaam_contract::{ActionRecord, DataClass, RecordId, SchemaVer, attrs, extract, timestamp};

use crate::cli::EmitArgs;
use crate::config::EmitSettings;
use crate::error::{Error, Result, failed};
use crate::exit::Exit;

/// The redaction policy a record declares when nothing names one.
///
/// The name the shipped `spec/redaction/default.yaml` carries. A default at all because a deployment
/// that has not renamed its policy should not need the flag; a *wrong* default is caught by the
/// service rather than tolerated, which is what makes having one safe.
pub const DEFAULT_REDACTION_POLICY: &str = "default-v1";

/// How long to wait for the sidecar's answer, in milliseconds.
///
/// Generous, because the sidecar sends its whole backlog ahead of a new record and the answer waits
/// on that. Bounded all the same: a hook that blocks for ever holds up whatever invoked it.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// How far behind this clock a live record's own timestamp may sit, in milliseconds.
///
/// Not a tolerance for wrong timestamps — a bound on which reading of an old `--at` is plausible. A
/// hook reporting an action it watched a moment ago is separated from this clock by scheduling and
/// by whatever skew there is between two hosts, which is small and which the deployment already
/// accounts for by recording the gap and alerting past this same figure. An `--at` further back than
/// that is not skew; it is history, and history is `--backfilled`'s to declare.
const LIVE_SKEW_MS: i64 = 5_000;

/// Schema version records are written under.
///
/// One constant rather than a flag. A caller cannot know more about the schema than the build it is
/// running, and a flag would let one claim a version whose fields it is not sending.
const SCHEMA_VER: SchemaVer = SchemaVer(1);

/// Builds one record from the arguments and sends it, reporting what became of it.
///
/// Validated locally before it is sent, so a record that cannot possibly be accepted fails here —
/// naming the field — rather than after a round trip that names it second-hand.
pub fn emit(settings: &EmitSettings, args: &EmitArgs, out: &mut dyn Write) -> Result<Exit> {
    let record = record(settings, args, now_ms())?;
    record
        .validate()
        .map_err(|error| Error::Rejected(error.to_string()))?;

    // Terminated here rather than by whoever sends it: the protocol is line-delimited, so a record
    // without its newline is a record the sidecar is still waiting for the rest of.
    let mut line =
        serde_json::to_vec(&record).map_err(|error| failed("serialising the record", &error))?;
    line.push(b'\n');

    // The exact bytes the socket would receive, which is what "the record it would send" means — and
    // what makes the dry run pipeable into a socket by hand, the first thing anyone integrating this
    // wants to try.
    if args.dry_run {
        out.write_all(&line)
            .map_err(|error| failed("writing the record", &error))?;
        return Ok(Exit::Ok);
    }

    let socket = settings.socket.as_deref().ok_or_else(|| {
        crate::error::config(format!(
            "no caller socket: pass --socket or set {}. It is the sidecar's record socket, at \
             <state-dir>/sockets/<agent>.sock by default",
            crate::config::ENV_SOCKET
        ))
    })?;
    let answer = exchange(socket, &line, Duration::from_millis(args.timeout_ms))?;
    report(&record.record_id, answer, out)
}

/// Turns one answer into what a person reads and what a script branches on.
///
/// The first line is always `<status> <record-id>`, whatever follows it, so a caller that wants the
/// identifier can take it without parsing prose.
fn report(id: &RecordId, answer: Answer, out: &mut dyn Write) -> Result<Exit> {
    let reason = answer.reason.unwrap_or_default();
    match answer.status {
        Status::Accepted => {
            emit_line(out, &format!("accepted {}\n", id.as_str()))?;
            Ok(Exit::Ok)
        }
        // A success, and the wording has to say so: the record is sealed on the sidecar's disk and
        // will go out when the service answers again. Nothing here is the caller's to redo.
        Status::Spooled => {
            emit_line(
                out,
                &format!(
                    "spooled {}\nthe service is not answering; the sidecar holds this record and \
                     keeps trying\n",
                    id.as_str()
                ),
            )?;
            Ok(Exit::Spooled)
        }
        // Degraded rather than failed: the same state `yaam check` calls degraded, seen from the
        // other end. The record was not taken, and what fixes it is not on this side.
        Status::SpoolFull => {
            emit_line(
                out,
                &format!(
                    "spool_full {}\nthe sidecar's spool is at its bound, so this record was not \
                     taken. Its backlog is going nowhere: check the service, then `yaam check` for \
                     what the store says\n",
                    id.as_str()
                ),
            )?;
            Ok(Exit::Degraded)
        }
        Status::Rejected => Err(Error::Rejected(match guidance(&reason) {
            Some(hint) => format!("{reason}\n  {hint}"),
            None => reason,
        })),
        // The sidecar's own failure, not a verdict on the record. Whoever runs the sidecar is the
        // one who can act on it, so the reason is passed through rather than interpreted.
        Status::Error => Err(Error::Failed(format!(
            "the sidecar could not take record {}: {reason}",
            id.as_str()
        ))),
    }
}

/// What to do about a rejection, for the ones whose bare reason leaves a caller stuck.
///
/// Each of these is a refusal a caller can act on and would not guess from the text alone: the
/// declared policy is checked against the deployment's, an unmasked body is the writer's to redact,
/// and attribution is decided by the socket rather than by the record. The rest of the reasons name
/// a field, which is already the whole answer.
fn guidance(reason: &str) -> Option<&'static str> {
    if reason.contains("redaction policy") {
        return Some(
            "pass --redaction-policy naming the policy this deployment applies: it is the `policy:` \
             field of its spec/redaction/*.yaml. A record may not declare a policy that was not the \
             one run, because its own account of what it redacted would then be false",
        );
    }
    if reason.contains("redaction pattern") {
        return Some(
            "the body has to be redacted before it is sent. A sidecar configured with \
             `redaction_policy_file` masks it on the way past; without one, the writer is the last \
             place that still knows what the value was",
        );
    }
    if reason.contains("socket belongs to") {
        return Some(
            "--agent has to name the agent whose socket this is: the socket is the evidence of who \
             is writing, so a record claiming another agent is refused rather than believed",
        );
    }
    None
}

/// Writes one report, turning a failed write into a failure of the command.
fn emit_line(out: &mut dyn Write, text: &str) -> Result<()> {
    out.write_all(text.as_bytes())
        .map_err(|error| failed("writing the report", &error))
}

/// Sends one line and reads the answer to it.
///
/// The failures here are told apart by what is known afterwards, not by which call returned them. A
/// connection that was refused, reset or closed without a word says the record was not taken: the
/// sidecar answers every record it takes, so no answer means nothing to answer for. A wait that ran
/// out says nothing of the kind — the answer may have been on its way — and calling that
/// "unreachable" would invite a re-send that stores the same action twice.
fn exchange(socket: &Path, line: &[u8], timeout: Duration) -> Result<Answer> {
    let stream = UnixStream::connect(socket).map_err(|error| {
        Error::Unreachable(format!(
            "{}: {error}. Nothing was recorded. The socket is bound by a sidecar serving this \
             caller, and it is the record socket rather than the `.read.sock` beside it",
            socket.display()
        ))
    })?;
    for set in [UnixStream::set_read_timeout, UnixStream::set_write_timeout] {
        set(&stream, Some(timeout)).map_err(|error| failed("bounding the socket wait", &error))?;
    }

    let mut writing = &stream;
    if let Err(error) = writing.write_all(line).and_then(|()| writing.flush()) {
        return Err(silence(socket, &error));
    }

    let mut answer = String::new();
    match BufReader::new(&stream).read_line(&mut answer) {
        Ok(0) => Err(silence(
            socket,
            &std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
        )),
        Ok(_) => serde_json::from_str(answer.trim()).map_err(|error| {
            Error::Failed(format!(
                "{} answered something this cannot read ({error}): {}. Whether the record was taken \
                 is unknown",
                socket.display(),
                answer.trim()
            ))
        }),
        Err(error) => Err(silence(socket, &error)),
    }
}

/// What an exchange that produced no answer means.
///
/// Two outcomes, and the difference is whether the socket said it was gone or merely said nothing. A
/// sidecar killed between spooling a record and answering for it would look like the first; that is
/// the narrow case this wording is wrong about, and it is why durability is the sidecar's rather than
/// the caller's — the record is on its disk either way, and re-sending would double it.
fn silence(socket: &Path, error: &std::io::Error) -> Error {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        return Error::Failed(format!(
            "no answer from {} in time ({error}). Whether the record was taken is unknown, so \
             sending it again would be a second record rather than a retry",
            socket.display()
        ));
    }
    Error::Unreachable(format!(
        "{} closed without answering ({error}), so nothing was recorded. The sidecar answers every \
         record it takes; it drops a connection from another user without a word, so this socket has \
         to belong to whoever runs this",
        socket.display()
    ))
}

/// Builds the record the arguments describe.
///
/// `now` is passed in rather than read here, so what this produces is a function of its arguments
/// and can be asserted on.
fn record(settings: &EmitSettings, args: &EmitArgs, now: i64) -> Result<ActionRecord> {
    let (at_ms, received_ms) = stamps(args, now)?;
    Ok(ActionRecord {
        record_id: RecordId::generate(),
        schema_ver: SCHEMA_VER,
        // Re-rendered from the milliseconds rather than passed through as the caller spelled it: an
        // offset is legal input and would put a second spelling of one instant in the store, where
        // the day a record is filed under is read back off this string.
        at: timestamp::format_ms(at_ms),
        received_at: timestamp::format_ms(received_ms),
        backfilled: args.backfilled,
        agent: settings.agent.clone(),
        agent_ver: args.agent_ver.clone(),
        correlation_id: args.correlation_id.clone(),
        action: args.action.clone(),
        outcome: args.outcome.into_contract(),
        attrs: declared_attrs(args)?,
        entities: args
            .entities
            .iter()
            .map(|spec| entity_ref(spec))
            .collect::<Result<Vec<_>>>()?,
        // Empty, and no flag can change it: see `crate::cli::EmitCli`.
        subjects: Vec::new(),
        visibility: args.visibility.into_contract(),
        team: args.team.clone(),
        data_class: DataClass::Internal,
        redaction_policy: args.redaction_policy.clone(),
        // Nothing was masked here. A sidecar that masks on the way past adds its own account, and a
        // caller that redacted before calling this can say so by masking and naming it there.
        fields_masked: Vec::new(),
        tags: args.tags.clone(),
        summary: args.summary.clone(),
    })
}

/// The two timestamps, in milliseconds: when the action happened, and when this learnt of it.
///
/// One function because the pair is one decision. `at` is display-only downstream and the received
/// time is what every ordering, window and join uses, so which of the two the flags move is the
/// whole of what a record's position in history depends on — and getting it wrong is not visible
/// afterwards, in a store nothing rewrites.
///
/// Three refusals, none of them a matter of taste:
///
/// - **`--backfilled` with no `--at`.** The flag's entire claim is that the received time came from
///   upstream, and with nothing to take it from there is only this clock — so the record would
///   assert, in a field, the one thing it did not do.
/// - **`--at` after now.** This process is the one recording the action, so an instant it has not
///   reached yet cannot be one the action happened at. There is no grace: a stamp from a clock
///   running ahead is still a record that claims to have happened after it was received.
/// - **`--at` further back than [`LIVE_SKEW_MS`], without `--backfilled`.** This one is the reason
///   the flag exists rather than being inferred from the timestamp. Such a record is coherent — it
///   happened then, this saw it now — so nothing downstream refuses it; it simply sorts and windows
///   at now, which is precisely the corruption a backfill exists to avoid. Refusing it here makes
///   the import say which of the two it meant, at the one moment anybody can still be asked.
fn stamps(args: &EmitArgs, now: i64) -> Result<(i64, i64)> {
    let Some(text) = args.at.as_deref() else {
        if args.backfilled {
            return Err(Error::Usage(
                "--backfilled needs --at: it says the received time came from the source, and \
                 without one there is nothing to take it from but this clock — which is what the \
                 flag denies. Name the source's own instant with --at, or drop --backfilled"
                    .to_owned(),
            ));
        }
        // The same instant twice, and that is honest: this process is both what saw the action and
        // the clock that read it.
        return Ok((now, now));
    };

    let at = timestamp::parse_ms(text).ok_or_else(|| {
        Error::Usage(format!(
            "--at {text} is not a timestamp this can read. It has to be RFC3339 — \
             `2026-08-20T09:14:02Z`, optionally with a `.sss` fraction and with an `+hh:mm` offset \
             in place of the `Z`. Coercing it would file the record at an instant nobody chose"
        ))
    })?;
    if at > now {
        return Err(Error::Usage(format!(
            "--at {text} is after this clock reads ({}). A record is something that happened, and \
             this process is the one recording it, so an instant it has not reached yet is not one \
             the action can have happened at",
            timestamp::format_ms(now)
        )));
    }
    if args.backfilled {
        // §6's exception, and the whole point of the flag: the source's instant is both timestamps,
        // so the record takes its place in history rather than at the moment of import.
        return Ok((at, at));
    }
    if now - at > LIVE_SKEW_MS {
        return Err(Error::Usage(format!(
            "--at {text} is further behind this clock ({}) than skew between two hosts accounts \
             for, so this record cannot have been watched happening. Pass --backfilled with it if \
             it comes from a source: that is what makes the received time the source's instant too, \
             and the received time is what every ordering, window and join reads. Without it this \
             would be stored as history that arrived today",
            timestamp::format_ms(now)
        )));
    }
    Ok((at, now))
}

/// Collects every attribute flag into one map.
///
/// Three flags rather than one that guesses: the type each key is declared with lives in the
/// deployment's `spec/attrs-schema.yaml`, which this process cannot read, so a value's shape is not
/// evidence of its type. A build number that happens to be all digits is the case that settles it.
fn declared_attrs(args: &EmitArgs) -> Result<BTreeMap<String, attrs::Value>> {
    let mut collected = BTreeMap::new();
    let sources: [(&str, &[String]); 3] = [
        ("--attr", &args.attrs),
        ("--attr-int", &args.attr_ints),
        ("--attr-bool", &args.attr_bools),
    ];
    for (flag, specs) in sources {
        for spec in specs {
            let (key, text) = pair(flag, spec)?;
            let value = match flag {
                "--attr-int" => attrs::Value::Int(text.parse::<i64>().map_err(|error| {
                    Error::Usage(format!("--attr-int {spec} is not a whole number ({error})"))
                })?),
                "--attr-bool" => attrs::Value::Bool(match text {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(Error::Usage(format!(
                            "--attr-bool {spec} needs `true` or `false`, not `{other}`"
                        )));
                    }
                }),
                _ => attrs::Value::Text(text.to_owned()),
            };
            // Refused rather than overwritten. A caller that named a key twice meant two things by
            // it, and only one of them would have been recorded.
            if collected.insert(key.to_owned(), value).is_some() {
                return Err(Error::Usage(format!(
                    "attribute `{key}` is given more than once"
                )));
            }
        }
    }
    Ok(collected)
}

/// Splits one `key=value` argument.
///
/// At the first `=`, because a value may contain one and a declared attribute key may not.
fn pair<'a>(flag: &str, spec: &'a str) -> Result<(&'a str, &'a str)> {
    let (key, value) = spec
        .split_once('=')
        .ok_or_else(|| Error::Usage(format!("{flag} {spec} is not `key=value`")))?;
    if key.is_empty() {
        return Err(Error::Usage(format!("{flag} {spec} names no key")));
    }
    Ok((key, value))
}

/// Reads one `kind:id` entity reference.
///
/// Primary, at [`extract::FIELD_CONFIDENCE`]: an argument is a structured field, and a caller naming
/// an entity is stating a fact rather than inferring one from prose. Split at the first `:` — an
/// entity kind cannot contain one and an identifier can.
fn entity_ref(spec: &str) -> Result<EntityRef> {
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
    Ok(EntityRef {
        kind: kind.to_owned(),
        id: id.to_owned(),
        role: entity::Role::Primary,
        confidence: extract::FIELD_CONFIDENCE,
    })
}

/// The host clock, in milliseconds since the epoch.
///
/// A clock set before 1970 still produces a stamp, and that stamp is what the host believed. The
/// contract's own validation is what refuses one it cannot read, so nothing here has to guess at a
/// repair.
fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use clap::Parser;

    use super::{DEFAULT_REDACTION_POLICY, emit, guidance, record};
    use crate::cli::EmitCli;
    use crate::config::{EmitSettings, Env};
    use crate::error::Error;
    use crate::exit::Exit;

    /// The arguments a hook would pass, plus whatever a test adds.
    fn parsed(extra: &[&str]) -> EmitCli {
        let mut args = vec![
            "yaam-emit",
            "--action",
            "deploy",
            "--outcome",
            "success",
            "--summary",
            "rolled the api service out to staging",
        ];
        args.extend_from_slice(extra);
        EmitCli::try_parse_from(args).expect("parsed")
    }

    fn settings(socket: PathBuf) -> EmitSettings {
        EmitSettings {
            socket: Some(socket),
            agent: "agent_a".to_owned(),
        }
    }

    /// A socket that reads one record and answers it, which is all a caller of this ever sees.
    ///
    /// The record is read before anything is answered, so a caller that never managed to send its
    /// line cannot pass this by being answered anyway.
    fn answering(dir: &std::path::Path, name: &str, answer: &'static str) -> PathBuf {
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::BufReader::new(&stream), &mut line)
                .expect("the record");
            assert!(line.contains("\"record_id\""), "{line}");
            let _ = stream.write_all(answer.as_bytes());
        });
        path
    }

    /// Every field the schema requires, from the arguments a hook actually passes.
    #[test]
    fn the_mechanical_fields_are_filled_in() {
        let cli = parsed(&[]);
        let built = record(
            &settings(PathBuf::from("/nowhere")),
            &cli.args,
            1_787_217_242_117,
        )
        .expect("built");

        built.validate().expect("a record the contract accepts");
        assert_eq!(built.at, "2026-08-20T09:14:02.117Z");
        assert_eq!(built.received_at, built.at, "one process, one clock");
        assert!(!built.backfilled);
        assert_eq!(built.schema_ver.0, 1);
        assert_eq!(built.agent, "agent_a");
        assert_eq!(built.redaction_policy, DEFAULT_REDACTION_POLICY);
        assert_eq!(built.record_id.as_str().len(), 26);
        // The decision that stays open, and the one the record cannot be talked into.
        assert!(built.subjects.is_empty());
        assert_eq!(built.data_class, yaam_contract::DataClass::Internal);
    }

    /// The instant `--at` names becomes both timestamps, which is what puts an imported record in
    /// its own place in history rather than at the moment of import.
    #[test]
    fn a_backfilled_record_takes_the_sources_instant_for_both_timestamps() {
        let cli = parsed(&["--at", "2023-05-01T12:00:00Z", "--backfilled"]);
        let built = record(
            &settings(PathBuf::from("/nowhere")),
            &cli.args,
            1_787_217_242_117,
        )
        .expect("built");

        built.validate().expect("a record the contract accepts");
        assert!(built.backfilled);
        assert_eq!(built.at, "2023-05-01T12:00:00.000Z");
        // The rule this exists for: `received_ms := at_ms`. Ordering, windowing and joins all read
        // the received time, so had this stayed at now the record would answer today's windows and
        // none of 2023's.
        assert_eq!(built.received_at, built.at);
    }

    /// An offset is legal input and is stored as the one spelling of the instant it names.
    #[test]
    fn an_offset_is_normalised_rather_than_stored_as_written() {
        let cli = parsed(&["--at", "2023-05-01T21:00:00+09:00", "--backfilled"]);
        let built =
            record(&settings(PathBuf::from("/nowhere")), &cli.args, i64::MAX).expect("built");
        assert_eq!(built.at, "2023-05-01T12:00:00.000Z");
    }

    /// `--at` alone is for the gap between watching an action and reporting it, and no further.
    #[test]
    fn a_live_record_may_name_its_own_instant_within_the_skew_a_hook_has() {
        let now = 1_787_217_242_117;
        let cli = parsed(&["--at", "2026-08-20T09:14:00Z"]);
        let built = record(&settings(PathBuf::from("/nowhere")), &cli.args, now).expect("built");

        assert!(!built.backfilled);
        assert_eq!(built.at, "2026-08-20T09:14:00.000Z");
        // Not equal, and that is the honest pair: the action is the source's instant, the receipt is
        // this clock's. It is also the gap §6's skew metric is measuring.
        assert_eq!(built.received_at, "2026-08-20T09:14:02.117Z");
    }

    /// Each refusal the two flags carry, and the reason has to name what to do about it.
    #[test]
    fn the_timestamp_a_record_cannot_honestly_claim_is_refused_before_anything_is_sent() {
        let now = 1_787_217_242_117;
        let cases: [(&[&str], &str); 5] = [
            // Malformed, and the message names the format rather than repairing the value.
            (&["--at", "last tuesday"], "RFC3339"),
            (&["--at", "2026-02-30T00:00:00Z"], "RFC3339"),
            // The future: records are history, whether or not the record calls itself a backfill.
            (&["--at", "2027-01-01T00:00:00Z"], "has not reached"),
            (
                &["--at", "2027-01-01T00:00:00Z", "--backfilled"],
                "has not reached",
            ),
            // The combination refused on purpose: a claim that the received time came from upstream,
            // with no upstream instant to have taken it from.
            (&["--backfilled"], "--backfilled needs --at"),
        ];
        for (extra, expected) in cases {
            let cli = parsed(extra);
            let error = record(&settings(PathBuf::from("/nowhere")), &cli.args, now)
                .expect_err("refused before a socket is opened");
            assert!(
                matches!(&error, Error::Usage(why) if why.contains(expected)),
                "{extra:?} produced {error}"
            );
        }
    }

    /// The refusal the flag exists for: an old `--at` on its own is a record that would be filed as
    /// having arrived today, and nothing downstream could tell.
    #[test]
    fn history_without_the_flag_that_declares_it_is_refused_naming_the_flag() {
        let cli = parsed(&["--at", "2023-05-01T12:00:00Z"]);
        let error = record(
            &settings(PathBuf::from("/nowhere")),
            &cli.args,
            1_787_217_242_117,
        )
        .expect_err("three years is not skew");
        let told = error.to_string();
        assert!(told.contains("--backfilled"), "{told}");
        assert!(told.contains("arrived today"), "{told}");
    }

    /// Two records from one set of arguments are two records, because the identifier is the
    /// idempotency key and a repeated one would be a write nobody performed.
    #[test]
    fn each_record_gets_its_own_identifier() {
        let cli = parsed(&[]);
        let settings = settings(PathBuf::from("/nowhere"));
        let first = record(&settings, &cli.args, 0).expect("built");
        let second = record(&settings, &cli.args, 0).expect("built");
        assert_ne!(first.record_id, second.record_id);
    }

    #[test]
    fn attributes_carry_the_type_the_flag_names() {
        let cli = parsed(&[
            "--attr",
            "build=1146",
            "--attr-int",
            "duration_ms=8200",
            "--attr-bool",
            "rolled_back=false",
        ]);
        let built = record(&settings(PathBuf::from("/nowhere")), &cli.args, 0).expect("built");

        // The case the three flags exist for: a build number is declared `string` and would be sent
        // as an integer by anything guessing from its shape.
        assert_eq!(
            built.attrs["build"],
            yaam_contract::attrs::Value::Text("1146".to_owned())
        );
        assert_eq!(
            built.attrs["duration_ms"],
            yaam_contract::attrs::Value::Int(8_200)
        );
        assert_eq!(
            built.attrs["rolled_back"],
            yaam_contract::attrs::Value::Bool(false)
        );
    }

    #[test]
    fn a_malformed_argument_is_a_usage_error_before_anything_is_sent() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["--attr", "nokey"],
            vec!["--attr", "=value"],
            vec!["--attr-int", "duration_ms=soon"],
            vec!["--attr-bool", "rolled_back=maybe"],
            vec!["--attr", "build=1", "--attr-int", "build=1"],
            vec!["--entity", "nocolon"],
            vec!["--entity", "deploy:"],
            vec!["--entity", ":api"],
        ];
        for extra in cases {
            let cli = parsed(&extra);
            let error = record(&settings(PathBuf::from("/nowhere")), &cli.args, 0)
                .expect_err("refused before a socket is opened");
            assert!(
                matches!(error, Error::Usage(_)),
                "{extra:?} produced {error}"
            );
        }
    }

    #[test]
    fn an_entity_argument_is_a_primary_reference_at_full_confidence() {
        // The identifier keeps its own colons; only the kind is split off.
        let cli = parsed(&["--entity", "deploy:api/staging#1146"]);
        let built = record(&settings(PathBuf::from("/nowhere")), &cli.args, 0).expect("built");
        let reference = &built.entities[0];
        assert_eq!(reference.kind, "deploy");
        assert_eq!(reference.id, "api/staging#1146");
        assert_eq!(reference.role, yaam_contract::entity::Role::Primary);
        assert!((reference.confidence - 1.0).abs() < f32::EPSILON);
    }

    /// A record the contract itself refuses never reaches a socket, and the reason names the field.
    #[test]
    fn a_record_the_contract_refuses_fails_here_rather_than_over_the_socket() {
        let cli = parsed(&["--visibility", "team"]);
        let mut out = Vec::new();
        let error = emit(
            &settings(PathBuf::from("/nowhere/at/all.sock")),
            &cli.args,
            &mut out,
        )
        .expect_err("a team-scoped record with no team");
        assert!(
            matches!(&error, Error::Rejected(why) if why.contains("team")),
            "{error}"
        );
        assert_eq!(error.exit(), Exit::Rejected);
    }

    /// `--dry-run` prints the line the socket would have received, and needs no socket.
    #[test]
    fn a_dry_run_needs_no_socket() {
        // The point of a dry run is seeing the record before there is a sidecar to send it to, so
        // demanding the socket that would have received it defeats it. `--agent` is still required,
        // and rightly: it is a field of the record being printed, not a detail of how it travels.
        let cli = parsed(&["--dry-run", "--agent", "agent_a"]);
        let resolved = EmitSettings::resolve(&cli.args, &Env::default())
            .expect("a dry run resolves without a socket");
        assert!(resolved.socket.is_none());

        let mut out = Vec::new();
        assert_eq!(
            emit(&resolved, &cli.args, &mut out).expect("printed"),
            Exit::Ok
        );
        assert_eq!(String::from_utf8(out).expect("utf-8").lines().count(), 1);
    }

    #[test]
    fn a_dry_run_prints_one_sendable_line() {
        let cli = parsed(&["--dry-run", "--tag", "lab"]);
        let mut out = Vec::new();
        let exit = emit(
            &settings(PathBuf::from("/nowhere/at/all.sock")),
            &cli.args,
            &mut out,
        )
        .expect("no socket is needed");
        assert_eq!(exit, Exit::Ok);

        let printed = String::from_utf8(out).expect("utf-8");
        assert_eq!(printed.lines().count(), 1, "the socket takes one line");
        let sent: yaam_contract::ActionRecord =
            serde_json::from_str(printed.trim()).expect("the line the sidecar would parse");
        assert_eq!(sent.tags, ["lab"]);
    }

    #[test]
    fn every_answer_becomes_its_own_exit_code() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cases: [(&'static str, Exit); 3] = [
            (r#"{"status":"accepted"}"#, Exit::Ok),
            (r#"{"status":"spooled"}"#, Exit::Spooled),
            (r#"{"status":"spool_full"}"#, Exit::Degraded),
        ];
        for (index, (answer, expected)) in cases.into_iter().enumerate() {
            let path = answering(dir.path(), &format!("caller-{index}.sock"), answer);
            let cli = parsed(&[]);
            let mut out = Vec::new();
            let exit = emit(&settings(path), &cli.args, &mut out).expect("answered");
            assert_eq!(exit, expected, "{answer}");

            // The identifier is on the first line whatever else is said, so a script can take it.
            let printed = String::from_utf8(out).expect("utf-8");
            let mut first = printed.lines().next().expect("a first line").split(' ');
            assert!(first.next().is_some_and(|status| answer.contains(status)));
            assert_eq!(first.next().map(str::len), Some(26), "{printed}");
        }
    }

    #[test]
    fn a_rejection_is_permanent_and_carries_its_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = answering(
            dir.path(),
            "caller.sock",
            r#"{"status":"rejected","reason":"record declares redaction policy `default-v1`, this deployment applies `strict-v2`"}"#,
        );
        let cli = parsed(&[]);
        let mut out = Vec::new();
        let error = emit(&settings(path), &cli.args, &mut out).expect_err("refused");
        assert_eq!(error.exit(), Exit::Rejected);
        // The reason, and what to do about it, rather than a code the caller has to look up.
        let told = error.to_string();
        assert!(told.contains("strict-v2"), "{told}");
        assert!(told.contains("--redaction-policy"), "{told}");
    }

    #[test]
    fn the_sidecars_own_failure_is_not_a_verdict_on_the_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = answering(
            dir.path(),
            "caller.sock",
            r#"{"status":"error","reason":"spool lock poisoned"}"#,
        );
        let cli = parsed(&[]);
        let mut out = Vec::new();
        let error = emit(&settings(path), &cli.args, &mut out).expect_err("failed");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("spool lock poisoned"));
    }

    #[test]
    fn a_socket_nothing_is_listening_on_is_unreachable_and_says_nothing_was_recorded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cli = parsed(&[]);
        let mut out = Vec::new();
        let error = emit(
            &settings(dir.path().join("absent.sock")),
            &cli.args,
            &mut out,
        )
        .expect_err("nothing is listening");
        assert_eq!(error.exit(), Exit::Unreachable);
        assert!(error.to_string().contains("Nothing was recorded"));
        assert!(out.is_empty(), "nothing happened, so nothing is reported");
    }

    /// A connection dropped without a word is what a socket belonging to another user looks like.
    #[test]
    fn a_socket_that_closes_without_answering_is_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("silent.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || drop(listener.accept()));

        let cli = parsed(&[]);
        let mut out = Vec::new();
        let error = emit(&settings(path), &cli.args, &mut out).expect_err("no answer");
        assert_eq!(error.exit(), Exit::Unreachable);
    }

    /// An answer this build cannot read leaves the outcome unknown, which is not the same as lost.
    #[test]
    fn an_unreadable_answer_does_not_claim_the_record_went_nowhere() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = answering(dir.path(), "caller.sock", "not json at all\n");
        let cli = parsed(&[]);
        let mut out = Vec::new();
        let error = emit(&settings(path), &cli.args, &mut out).expect_err("unreadable");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("unknown"), "{error}");
    }

    /// A wait that expires says the outcome is unknown, and warns against a re-send: the record may
    /// have been taken, and a second one would be a second record rather than a retry.
    #[test]
    fn a_silent_socket_times_out_without_claiming_either_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mute.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        // Held, not dropped: the connection stays open and says nothing, which is the case a bare
        // read would wait out for ever.
        let held = std::thread::spawn(move || {
            let accepted = listener.accept().expect("accept");
            std::thread::sleep(std::time::Duration::from_millis(500));
            drop(accepted);
        });

        let cli = parsed(&["--timeout-ms", "150"]);
        let mut out = Vec::new();
        let error = emit(&settings(path), &cli.args, &mut out).expect_err("timed out");
        assert_eq!(error.exit(), Exit::Failed);
        assert!(error.to_string().contains("unknown"), "{error}");
        held.join().expect("the holder");
    }

    #[test]
    fn the_rejections_a_caller_cannot_act_on_alone_get_told_what_to_do() {
        assert!(
            guidance("record declares redaction policy `a`, this deployment applies `b`")
                .is_some_and(|hint| hint.contains("--redaction-policy"))
        );
        assert!(
            guidance(
                "body still matches redaction pattern `card_like`; the writer must redact first"
            )
            .is_some_and(|hint| hint.contains("redacted"))
        );
        assert!(
            guidance("socket belongs to `agent_a`, record claims `agent_b`")
                .is_some_and(|hint| hint.contains("--agent"))
        );
        // A reason that already names the field it is about needs nothing added to it.
        assert!(guidance("action is empty").is_none());
    }

    /// The settings refuse rather than guess, and say which variable would have supplied them.
    ///
    /// The socket is refused at the send, not at the resolve: a dry run has none to name, and moving
    /// the check is what lets it print a record before a sidecar exists. The refusal itself is
    /// unchanged, and still names the variable that would have supplied it.
    #[test]
    fn a_socket_and_an_agent_are_required_and_can_come_from_the_environment() {
        let cli = parsed(&["--agent", "agent_a"]);
        let resolved = EmitSettings::resolve(&cli.args, &Env::default()).expect("resolves");
        assert!(resolved.socket.is_none());
        let mut sink = Vec::new();
        let missing = emit(&resolved, &cli.args, &mut sink).expect_err("nothing names a socket");
        assert_eq!(missing.exit(), Exit::Config);
        assert!(missing.to_string().contains("YAAM_SOCKET"));

        let cli = parsed(&[]);

        let no_agent = EmitSettings::resolve(
            &cli.args,
            &Env {
                socket: Some("/run/a.sock".into()),
                ..Env::default()
            },
        )
        .expect_err("nothing names an agent");
        assert!(no_agent.to_string().contains("YAAM_AGENT"));

        let resolved = EmitSettings::resolve(
            &cli.args,
            &Env {
                socket: Some("/run/a.sock".into()),
                agent: Some("agent_a".into()),
                ..Env::default()
            },
        )
        .expect("both from the environment");
        assert_eq!(resolved, settings(PathBuf::from("/run/a.sock")));

        // And a flag beats the variable, in the one order this workspace uses everywhere.
        let flagged = parsed(&["--socket", "/run/b.sock", "--agent", "agent_b"]);
        let resolved = EmitSettings::resolve(
            &flagged.args,
            &Env {
                socket: Some("/run/a.sock".into()),
                agent: Some("agent_a".into()),
                ..Env::default()
            },
        )
        .expect("resolved");
        assert_eq!(resolved.socket, Some(PathBuf::from("/run/b.sock")));
        assert_eq!(resolved.agent, "agent_b");
    }
}
