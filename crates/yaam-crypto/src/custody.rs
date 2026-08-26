//! Where the subject key comes from.
//!
//! [`SubjectKey`] is the one secret in this workspace that can never be rotated. Every pseudonym
//! ever derived is a function of it, those pseudonyms are in published paths and in tombstones that
//! are never deleted, and a leak de-pseudonymises every backup ever taken rather than everything
//! written after the leak. A secret of that standing is one a deployment eventually wants held by a
//! keychain, an HSM or a key service instead of by a file on the host.
//!
//! The seam for that is here before anything needs it, and the timing is the whole point: after the
//! first record is sealed, changing where this key is fetched from means changing how a live,
//! irreplaceable key reaches a running store — with no way to test the new path against the old one,
//! because there is only ever one key and no second one to compare against. Before then it is a
//! refactor.
//!
//! [`SubjectKeySource`] is the protocol. [`SubjectKeyFile`] is the only implementation that ships,
//! and it is what `--subject-key-file` already did, moved behind the trait unchanged. No keychain or
//! key-service client ships here, for the same reason none ships for
//! [`crate::keystore::KeyWrapper`]: the deployment that has the service is the one that can talk to
//! it, and a stub in this crate would be a dependency for everybody and a working implementation for
//! nobody.

use std::path::PathBuf;

use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::subject::SubjectKey;

/// Where a process gets the subject key from, at startup.
///
/// # What this deliberately does not allow
///
/// The shape is chosen against the ways an unrotatable secret gets copied, not for elegance:
///
/// - **No borrow of the key, and so no second place it lives.** [`SubjectKeySource::fetch`] hands
///   over an owned [`SubjectKey`] and the source keeps nothing. A source holds a *locator* — a path,
///   a key id, a service endpoint — never key material, so whatever can read a source's own state
///   learns nothing from it. There is deliberately no `fn key(&self) -> &SubjectKey`, which would
///   make every source a second copy of the secret for the life of the process.
/// - **No caching, and nowhere to put one.** [`SubjectKey`] has no [`Clone`], so the value `fetch`
///   returns is the only one there is: it goes straight into the resolver that derives with it and is
///   zeroized when that drops. A caller wanting a second copy has to fetch again, which is
///   deliberately the visible thing to do. An implementation must not memoise either — a cached key
///   is a key that outlives the credential that was allowed to fetch it.
/// - **Nothing to log.** No method here returns key material or anything derived from it.
///   [`SubjectKeySource::custody`] is prose about *where*, because it reaches a startup log, which is
///   the most widely copied text a deployment produces.
/// - **No fallback, no default, no generated key.** A source that cannot answer returns an error and
///   nothing else. It may not mint a key, and it may not fall back to a second source: a key that is
///   not the store's own key derives a second pseudonym for every subject already in it, half its
///   records become unreachable by an erasure request, and nothing afterwards can relate the two
///   halves. That failure is why the only alternative to the key is the error, and why the startup
///   path above treats an error as a refusal to run.
///
/// # The contract a source that is not a file has to meet
///
/// [`SubjectKeyFile`] exercises none of the following, so they are stated here rather than
/// discovered by the first implementation that needs them:
///
/// - **A fetch may block, and is only ever called at startup.** The key is fetched while the
///   process is coming up, before the service accepts a request, and never again — no record write
///   reaches this trait, so a slow fetch costs startup latency and not request latency. A source
///   making a network call owes that call its own bounded timeout: an unbounded one is a service that
///   hangs without saying why, which under a supervisor is worse than exiting, because nothing
///   restarts it into a working state.
/// - **A transient failure is still a startup refusal.** There is no retry loop above this and no
///   degraded mode to fall into — a store that came up without the key would refuse every
///   subject-derived record it was sent, or worse, be reconfigured by an operator into writing bodies
///   in the clear. A source may retry internally, bounded; what it may not do is answer with
///   anything other than the key or an error naming what it could not reach.
/// - **Repeat fetches must return the same bytes.** A caller fetches once per pipeline it opens:
///   once for the service, once per operator command. An implementation must therefore tolerate more
///   than one call, and every call must return the same key. A source that resolved a mutable alias
///   — a key-service alias whose current version moves — would hand one subject two pseudonyms the
///   first time it moved, and this store has no correction path for that. Pin the version; do not
///   follow the alias.
///
/// [`Send`] and [`Sync`] so a deployment can build its source wherever it builds the rest of its
/// configuration and hand it to the startup path on another thread. Nothing here is called after
/// startup.
pub trait SubjectKeySource: Send + Sync {
    /// Fetches the subject key.
    ///
    /// # Errors
    /// [`Error::SubjectKeyUnavailable`] where the key could not be reached at all, and
    /// [`Error::SubjectKeyNotHex`] or [`Error::SubjectKeyLength`] where something arrived and was not
    /// a key. Every one of them stops the process; see the trait's own note on why there is no third
    /// answer.
    fn fetch(&self) -> Result<SubjectKey>;

    /// Where this source takes the key from, in the words a startup log uses.
    ///
    /// Never a secret, and never derived from one: an operator reading this is asking which custody
    /// an irreplaceable key is in, and the answer is a locator. Defaulted, because a deployment's own
    /// source need not name itself to work — and it is the only method here with a default, since a
    /// source that cannot fetch is not a source.
    fn custody(&self) -> String {
        "an unnamed source".to_owned()
    }
}

/// The subject key as hex in a file.
///
/// What `--subject-key-file` has always accepted: [`SUBJECT_KEY_LEN`](crate::SUBJECT_KEY_LEN) bytes
/// of hex, with trailing newlines not part of the secret. A file rather than a value for the reason
/// the key-wrapping passphrase is a file — an argument is in the process table and a variable is in
/// every child's environment.
///
/// It is also the weakest custody there is: the file *is* the key to whoever can read it, and no
/// call to anything else stands between a copied disk and every pseudonym the store has ever
/// derived. That is the state a keychain or key-service source exists to leave, and the reason
/// [`SubjectKeySource`] is here before the first record is sealed rather than when someone gets to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectKeyFile {
    /// The file to read. A path, never its contents: this struct is cloned into configuration and
    /// formatted into errors, and neither may carry the secret.
    path: PathBuf,
}

impl SubjectKeyFile {
    /// Names the file the key is read from.
    ///
    /// Nothing is read here. A source is a locator, and the read happens in
    /// [`SubjectKeySource::fetch`], so an absent or unreadable file is one refusal at startup rather
    /// than a construction that can fail anywhere a source is built.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SubjectKeySource for SubjectKeyFile {
    /// Reads the file and takes the key from its hex.
    ///
    /// Trailing whitespace goes, because a file written by `echo` and one written by a secret manager
    /// would otherwise be two different secrets — and here that means two pseudonyms for one subject,
    /// which nothing can relate again afterwards. No error quotes the content: a startup failure that
    /// did would put the secret into every log that captured it.
    fn fetch(&self) -> Result<SubjectKey> {
        let mut read = std::fs::read_to_string(&self.path)
            .map_err(|error| Error::SubjectKeyUnavailable(format!("cannot read it: {error}")))?;
        let key = SubjectKey::from_hex(read.trim());
        // The buffer held the hex form of the secret, and it outlives the borrow above.
        read.zeroize();
        key
    }

    fn custody(&self) -> String {
        format!("the file {}", self.path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::Canon;

    /// A key file holding `hex`, in a directory that goes away with the test.
    fn key_file(hex: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("subject.key");
        std::fs::write(&path, hex).expect("written");
        (dir, path)
    }

    /// Hex with no structure to it. Any 32 bytes are a key; these are not special.
    const HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    /// The pseudonym `key` gives one reference, which is the only observable a key has.
    fn pseudonym(key: &SubjectKey) -> String {
        key.derive(Canon::CURRENT, "order_ref:abcd1234")
            .expect("derived")
            .hash
            .as_str()
            .to_owned()
    }

    /// The vector is the one [`crate::subject`]'s known-answer test holds, so this asserts the thing
    /// a deployment actually cares about: a key file that produced a store's existing pseudonyms
    /// produces the same ones through this source. A source that fetched correctly but derived
    /// differently would be indistinguishable from a wrong key, and every record written afterwards
    /// would be filed under a hash no erasure request for those subjects reaches.
    #[test]
    fn a_file_of_hex_derives_the_pseudonyms_already_in_a_store() {
        let (_dir, path) = key_file(HEX);
        let fetched = SubjectKeyFile::at(&path).fetch().expect("fetched");
        assert_eq!(
            pseudonym(&fetched),
            "s_fea92042d09db802208eceb305b1dc4238b77f2be0e41f1d16ed489b0eecb902"
        );
        assert_eq!(
            pseudonym(&fetched),
            pseudonym(&SubjectKey::from_hex(HEX).expect("hex key")),
            "fetching a key must be the same as being handed it"
        );
    }

    /// The property that makes `echo` and a secret manager write one secret rather than two.
    #[test]
    fn trailing_whitespace_is_not_part_of_the_secret() {
        let plain = key_file(HEX);
        let newline = key_file(&format!("{HEX}\r\n"));
        let fetched = |(_dir, path): &(tempfile::TempDir, PathBuf)| {
            pseudonym(&SubjectKeyFile::at(path).fetch().expect("fetched"))
        };
        assert_eq!(fetched(&plain), fetched(&newline));
    }

    /// The rule a key service has to honour and a file gets for free: one source, one key, however
    /// often it is asked. A subject whose second fetch differs has two pseudonyms and no way back.
    #[test]
    fn two_fetches_of_one_source_return_one_key() {
        let (_dir, path) = key_file(HEX);
        let source = SubjectKeyFile::at(&path);
        assert_eq!(
            pseudonym(&source.fetch().expect("fetched")),
            pseudonym(&source.fetch().expect("fetched again"))
        );
    }

    /// A source that cannot answer says so. It does not mint a key, which would seal the store's next
    /// records under a secret that reaches none of the ones already in it.
    #[test]
    fn an_unreachable_file_is_an_error_and_not_a_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = SubjectKeyFile::at(dir.path().join("absent"));
        let err = source.fetch().expect_err("nothing to read");
        assert!(
            matches!(err, Error::SubjectKeyUnavailable(ref why) if why.contains("cannot read it")),
            "{err}"
        );
    }

    /// Held apart from the above: these say key material arrived and was not a key, which is a file
    /// to fix rather than custody to reach.
    #[test]
    fn a_file_that_is_not_a_key_is_refused_rather_than_padded() {
        let (_dir, path) = key_file("not hex");
        assert!(matches!(
            SubjectKeyFile::at(&path).fetch(),
            Err(Error::SubjectKeyNotHex)
        ));

        let (_short_dir, short) = key_file(&HEX[..32]);
        assert!(matches!(
            SubjectKeyFile::at(&short).fetch(),
            Err(Error::SubjectKeyLength {
                expected: 32,
                got: 16
            })
        ));
    }

    /// What a source says about itself reaches a startup log, so it says where and never what.
    #[test]
    fn what_a_source_says_about_itself_is_not_a_secret() {
        let (_dir, path) = key_file(HEX);
        let source = SubjectKeyFile::at(&path);
        let said = format!("{} {:?}", source.custody(), source);
        assert!(said.contains("subject.key"), "{said}");
        assert!(!said.contains("5a5a"), "the key must not reach a log line");
    }

    /// The seam is usable behind a trait object, which is what lets a startup path choose a backend
    /// without the code below it learning which one it got.
    #[test]
    fn a_source_is_usable_without_naming_its_backend() {
        let (_dir, path) = key_file(HEX);
        let source: Box<dyn SubjectKeySource> = Box::new(SubjectKeyFile::at(&path));
        assert!(source.custody().contains("subject.key"));
        source.fetch().expect("fetched through the trait");
    }

    /// A source need not name itself to work, and the default says nothing untrue about custody.
    #[test]
    fn a_source_that_names_no_custody_still_fetches() {
        struct Anonymous;
        impl SubjectKeySource for Anonymous {
            fn fetch(&self) -> Result<SubjectKey> {
                SubjectKey::from_hex(HEX)
            }
        }
        assert_eq!(Anonymous.custody(), "an unnamed source");
        Anonymous.fetch().expect("fetched");
    }
}
