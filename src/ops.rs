//! Operations on one configured store, bound in the routed space ahead of the inspection
//! resources (`docs/storage-backends.md`, section 8): `urn:secret:store:name:{store}:reencrypt`
//! encrypts an `age-file` store's plaintext items in place (ledger #4488).
//!
//! Each is a Sink, never cacheable, and answers `text/plain` with one sentence per item and no
//! value. Every capability check and the presence gate come before any store is asked anything.

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, EndpointSpace, Error, Invocation, ReprType,
    Representation, Result, UriTemplate, Verb,
};

use crate::store::{RoutingBackend, StoreKind};
use crate::{PresenceGate, XSD_STRING};

/// `urn:secret:store:name:{store}:reencrypt`: encrypt every plaintext item of one `age-file`
/// store, in place.
pub const REENCRYPT_TEMPLATE: &str = "urn:secret:store:name:{store}:reencrypt";

/// Bind the store operations into `space`, ahead of whatever is bound after them (the inspection
/// resource `urn:secret:store:name:{store}` would otherwise take their names).
pub(crate) fn bind(
    space: EndpointSpace,
    routing: Arc<RoutingBackend>,
    gate: Arc<dyn PresenceGate>,
) -> EndpointSpace {
    space.bind(
        UriTemplate::parse(REENCRYPT_TEMPLATE).expect("valid template"),
        Reencrypt { routing, gate },
    )
}

/// The reencrypt operation.
struct Reencrypt {
    routing: Arc<RoutingBackend>,
    gate: Arc<dyn PresenceGate>,
}

#[async_trait]
impl Endpoint for Reencrypt {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Sink {
            return Err(Error::Endpoint(format!(
                "{REENCRYPT_TEMPLATE} is a Sink: it rewrites the store"
            )));
        }
        let store = inv
            .bindings
            .get("store")
            .map(|s| s.to_string())
            .ok_or_else(|| Error::MissingArgument("store".into()))?;
        // The kernel enforced the declared `urn:cap:secret:write:*` floor; each item's own write
        // scope is checked below, item by item, and an item it does not allow is never read.
        let config = self.routing.config();
        let spec = config
            .store(&store)
            .ok_or_else(|| Error::NotFound(format!("no store named `{store}` is configured")))?;
        if !matches!(spec.kind(), StoreKind::AgeFile { .. }) {
            return Err(Error::Conflict(format!(
                "the store {store} is a {} store, which does not encrypt its items; only an \
                 age-file store can be reencrypted. To move a file store in place, configure it \
                 as `kind = \"age-file\"` with the same `path`, then reencrypt it",
                spec.kind().name()
            )));
        }
        if spec.read_only() {
            return Err(Error::Conflict(format!(
                "the store {store} is read-only (`write = false`), so it cannot be reencrypted"
            )));
        }
        // Presence last, before the store is touched: asked whether or not anything needs
        // converting, so the prompt says nothing about what the store holds.
        self.gate
            .require(&format!("Encrypt the secrets in the store {store}"))?;
        let backend = self
            .routing
            .backend(&store)
            .expect("a configured store has a backend");
        let may_write = |name: &str| {
            inv.capability
                .allows(&format!("urn:cap:secret:write:{name}"))
        };
        let report = backend.reencrypt(&may_write)?;
        if !report.complete() {
            return Err(Error::Endpoint(report.to_string()));
        }
        // Never cacheable (the default), and no value in it.
        Ok(Representation::new(
            ReprType::new("text/plain"),
            report.to_string().into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "secret-store-reencrypt"
    }

    fn describe(&self) -> Description {
        Description::new("secret-store-reencrypt")
            .summary(
                "Encrypt, in place, every plaintext secret of one age-file store (a store moved \
                 from `file` keeps its old items as plaintext until each is written): one item at \
                 a time, each a temporary file renamed over the old one, after a backup copy of \
                 the store's directory beside it. Idempotent: an item already encrypted is left \
                 unchanged, and a run with nothing to convert makes no backup. Only items whose \
                 write scope (`urn:cap:secret:write:<name>`) the caller holds are read or named. \
                 Asks for presence (macOS Touch ID) after the capability check. Answers one line \
                 per item and never a value; never cached.",
            )
            .input(store_arg())
            .output("text/plain")
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("encrypt one age-file store's plaintext items in place")
                    .requires("urn:cap:secret:write:*")
                    .input(store_arg())
                    .output("text/plain"),
            )
    }
}

fn store_arg() -> ArgSpec {
    ArgSpec::new("store")
        .summary("the configured store's name (the `{store}` URI slot)")
        .class(XSD_STRING)
        .binding()
}
