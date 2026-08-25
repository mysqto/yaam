//! The spec directory `--infer-entities` names, for whichever command named it.
//!
//! Two commands read entity references out of prose now, and both are handed a directory rather
//! than a pair of files: `yaam-emit --infer-entities` lifts references onto a record it is about to
//! write, and `yaam-read bundle --infer-entities` turns a request's own prose into the keys it looks
//! up. What they do with the result could hardly be more different — see [`crate::read`] for why the
//! precision calculus inverts between them — but *loading* is one thing, and a second copy of it
//! would be a second set of error messages for the same misconfigured directory.
//!
//! Reading these two files is not opening a store. They are configuration, exactly as they are for
//! the emitter: read, never written, and nothing else in the directory is touched.

use std::path::Path;

use yaam_contract::entity::Registry;
use yaam_contract::extract::Extractor;

use crate::error::{Error, Result, config};

/// What an identifier is, inside the directory `--infer-entities` names.
pub const ENTITIES_FILE: &str = "entities.yaml";

/// When prose is evidence that one was meant, in the same directory.
pub const EXTRACTORS_FILE: &str = "extractors.yaml";

/// Loads the extraction rules out of the spec directory `--infer-entities` names.
///
/// Both files are required. A directory with no `extractors.yaml` would leave a caller that asked
/// for inference with nothing inferred and no way to tell — the flag is the request, so being
/// unable to honour it is a configuration failure rather than a quiet nothing.
///
/// # Errors
/// If either file cannot be read, or holds something the rules cannot be built from.
pub fn load(dir: &Path) -> Result<Extractor> {
    let registry = Registry::from_yaml(&text(dir, ENTITIES_FILE)?)
        .map_err(|error| unusable(dir, ENTITIES_FILE, &error))?;
    Extractor::from_yaml(registry, &text(dir, EXTRACTORS_FILE)?)
        .map_err(|error| unusable(dir, EXTRACTORS_FILE, &error))
}

/// Reads one file of the spec directory, naming what the directory is expected to be.
fn text(dir: &Path, file: &str) -> Result<String> {
    std::fs::read_to_string(dir.join(file)).map_err(|error| {
        config(format!(
            "--infer-entities {}: {error}. It names a spec directory, which is where {ENTITIES_FILE} \
             and {EXTRACTORS_FILE} live — the same pair the deployment this talks to reads",
            dir.join(file).display()
        ))
    })
}

/// A spec file that was read and could not be used.
fn unusable(dir: &Path, file: &str, cause: &dyn std::fmt::Display) -> Error {
    config(format!(
        "--infer-entities {}: {cause}",
        dir.join(file).display()
    ))
}
