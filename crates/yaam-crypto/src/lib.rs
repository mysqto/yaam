//! Sealing, and the key lifecycle that makes erasure real.
//!
//! The scheme in one paragraph: each record gets its own data key. That key is split into one share
//! per named subject, and each share is wrapped under a key belonging to that subject for a given
//! epoch. Unsealing needs *every* share, so destroying any one subject's key renders the body
//! permanently unreadable — in every copy, including backups, which is the property that file
//! rewriting cannot deliver.
//!
//! The types here exist to make the failure modes unrepresentable rather than documented:
//! a [`Nonce`] can only come from a CSPRNG, and a [`Dek`] can only be derived from a full share set.
//!
//! Every seal and unseal needs a [`keystore::KeyStore`] to wrap and unwrap the shares, and takes
//! one as an argument. There is deliberately no ambient store: the consumers are async, so a store
//! installed in a thread-local would disappear the moment an `.await` moved the task to another
//! worker thread — and a crypto API whose key custody is invisible at the call site invites the
//! misuse it should prevent.

#![forbid(unsafe_code)]

pub mod block;
pub mod error;
pub mod keystore;
pub mod seal;

pub use error::{Error, Result};
pub use seal::{BareShare, Dek, Epoch, Nonce, SealedBody, WrappedShare};
