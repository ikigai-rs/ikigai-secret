//! Operations on one configured store, bound in the routed space ahead of the inspection
//! resources (`docs/storage-backends.md`, section 8):
//!
//! - `urn:secret:store:name:{store}:reencrypt` encrypts an `age-file` store's plaintext items in
//!   place (ledger #4488);
//! - `urn:secret:store:name:{to}:copy` copies one secret from another store into this one, and
//!   never deletes the source (ledger #4491).
//!
//! Each is a Sink, never cacheable, and answers `text/plain` in sentences with no value. Every
//! capability check and the presence gate come before any store is asked anything.

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ActionSpec, ArgSpec, Description, Endpoint, EndpointSpace, Error, InputGroup, Invocation,
    ReprType, Representation, Result, UriTemplate, Verb,
};

use crate::store::{RoutingBackend, StoreKind};
use crate::{refuse_deny_shaped, PresenceGate, XSD_STRING};

/// The XSD `boolean` datatype IRI, for `replace`.
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";

/// `urn:secret:store:name:{store}:reencrypt`: encrypt every plaintext item of one `age-file`
/// store, in place.
pub const REENCRYPT_TEMPLATE: &str = "urn:secret:store:name:{store}:reencrypt";

/// `urn:secret:store:name:{to}:copy`: copy one secret from the store `from=` into the store
/// `{to}`, never deleting the source.
pub const COPY_TEMPLATE: &str = "urn:secret:store:name:{to}:copy";

/// Bind the store operations into `space`, ahead of whatever is bound after them (the inspection
/// resource `urn:secret:store:name:{store}` would otherwise take their names).
pub(crate) fn bind(
    space: EndpointSpace,
    routing: Arc<RoutingBackend>,
    gate: Arc<dyn PresenceGate>,
) -> EndpointSpace {
    space
        .bind(
            UriTemplate::parse(REENCRYPT_TEMPLATE).expect("valid template"),
            Reencrypt {
                routing: Arc::clone(&routing),
                gate: Arc::clone(&gate),
            },
        )
        .bind(
            UriTemplate::parse(COPY_TEMPLATE).expect("valid template"),
            Copy { routing, gate },
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

/// The copy operation (`docs/storage-backends.md`, section 8): how an install moves its secrets
/// into another store, one name at a time, after adding a `[secret]` section.
struct Copy {
    routing: Arc<RoutingBackend>,
    gate: Arc<dyn PresenceGate>,
}

/// The secret name a copy is asked for: `name=`, or the piped `content` (one name, a trailing
/// newline dropped), exactly one of them.
fn copy_name(inv: &Invocation<'_>) -> Result<String> {
    let given = |arg: &str| -> Result<Option<String>> {
        if !inv.request.args.contains_key(arg) {
            return Ok(None);
        }
        let text = inv.inline_str(arg)?;
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(text);
        Ok((!text.is_empty()).then(|| text.to_string()))
    };
    match (given("name")?, given("content")?) {
        (Some(name), None) | (None, Some(name)) => Ok(name),
        (Some(_), Some(_)) => Err(Error::InvalidArgument {
            name: "name".into(),
            detail: "the secret to copy is named twice, as `name=` and as piped content; give it \
                     once"
                .into(),
        }),
        (None, None) => Err(Error::MissingArgument("name".into())),
    }
}

#[async_trait]
impl Endpoint for Copy {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Sink {
            return Err(Error::Endpoint(format!(
                "{COPY_TEMPLATE} is a Sink: it writes the store `{{to}}`"
            )));
        }
        let to = inv
            .bindings
            .get("to")
            .map(|s| s.to_string())
            .ok_or_else(|| Error::MissingArgument("to".into()))?;
        let name = copy_name(inv)?;
        // Before the capability check: no grant could cover such a name.
        refuse_deny_shaped(&name, "name")?;
        // The kernel enforced the declared floors (some read grant and some write grant); these
        // are the exact name's, both needed, since a copy reads the secret and writes it.
        for (scope, does) in [
            (format!("urn:cap:secret:read:{name}"), "reads"),
            (format!("urn:cap:secret:write:{name}"), "writes"),
        ] {
            if !inv.capability.allows(&scope) {
                return Err(Error::Denied(
                    format!(
                        "copying `{name}` {does} it, so it requires `urn:cap:secret:read:{name}` \
                         and `urn:cap:secret:write:{name}`; missing `{scope}`"
                    )
                    .into(),
                ));
            }
        }
        let from = inv.inline_str("from")?.to_string();
        let replace = if inv.request.args.contains_key("replace") {
            match inv.inline_str("replace")? {
                "true" => true,
                "false" => false,
                other => {
                    return Err(Error::InvalidArgument {
                        name: "replace".into(),
                        detail: format!("`{other}` is not `true` or `false`"),
                    })
                }
            }
        } else {
            false
        };
        // The configuration alone, before any store is asked.
        let config = self.routing.config();
        let target = config
            .store(&to)
            .ok_or_else(|| Error::NotFound(format!("no store named `{to}` is configured")))?;
        let source = config.store(&from).ok_or_else(|| Error::InvalidArgument {
            name: "from".into(),
            detail: format!("no store named `{from}` is configured"),
        })?;
        if from == to {
            return Err(Error::InvalidArgument {
                name: "from".into(),
                detail: format!(
                    "`{name}` would be copied from the store {to} into itself, which changes \
                     nothing; name the store it comes from"
                ),
            });
        }
        if matches!(source.kind(), StoreKind::SecureEnclave { .. }) {
            return Err(Error::Conflict(format!(
                "the store {from} is a secure-enclave store, whose keys never leave it, so \
                 nothing can be copied from it"
            )));
        }
        if matches!(target.kind(), StoreKind::Fnox { .. }) {
            return Err(Error::Conflict(format!(
                "the store {to} is a fnox store, which is read-only, so nothing can be copied \
                 into it"
            )));
        }
        if target.read_only() {
            return Err(Error::Conflict(format!(
                "the store {to} is read-only (`write = false`), so nothing can be copied into it"
            )));
        }
        if !target.writable() {
            return Err(Error::Conflict(format!(
                "the store {to} is a {} store, which holds no values, so nothing can be copied \
                 into it",
                target.kind().name()
            )));
        }
        let into = self
            .routing
            .backend(&to)
            .expect("a configured store has a backend");
        let out_of = self
            .routing
            .backend(&from)
            .expect("a configured store has a backend");
        into.accepts_writes(&name)?;
        // Presence last, before either store is touched: asked whether or not the source holds
        // the name, so the prompt says nothing about either store.
        self.gate.require(&format!(
            "Copy secret {name} from the store {from} to the store {to}"
        ))?;
        let value = out_of.get(&name)?.ok_or_else(|| {
            Error::NotFound(format!(
                "the store {from} holds no secret `{name}`, so nothing was copied"
            ))
        })?;
        // What the target holds: `None` when it cannot be read and `replace` was asked for,
        // since replacing does not need to read what is there (which may be what is wrong).
        let held = match into.get(&name) {
            Ok(held) => Some(held),
            Err(_) if replace => None,
            Err(e) => return Err(e),
        };
        let answer = match held {
            Some(Some(held)) if held == value => format!(
                "The store {to} already holds the same value for `{name}`, so nothing was \
                 written. The store {from} still holds it."
            ),
            Some(Some(_)) if !replace => {
                return Err(Error::Conflict(format!(
                    "the store {to} already holds a different value for `{name}`, so nothing was \
                     copied; copy again with replace=true to replace it"
                )))
            }
            Some(Some(_)) | None => {
                into.replace(&name, &value)?;
                format!(
                    "Replaced `{name}` in the store {to} with the value from the store {from}. \
                     The store {from} still holds it."
                )
            }
            Some(None) => {
                if !into.create(&name, &value)? {
                    return Err(Error::Conflict(format!(
                        "`{name}` was written into the store {to} while it was being copied, so \
                         nothing was copied; copy again"
                    )));
                }
                format!(
                    "Copied `{name}` from the store {from} into the store {to}. The store {from} \
                     still holds it."
                )
            }
        };
        // Never cacheable (the default), and no value in it.
        Ok(Representation::new(
            ReprType::new("text/plain"),
            answer.into_bytes(),
        ))
    }

    fn name(&self) -> &str {
        "secret-store-copy"
    }

    fn describe(&self) -> Description {
        let to = || {
            ArgSpec::new("to")
                .summary("the store to copy into (the `{to}` URI slot)")
                .class(XSD_STRING)
                .binding()
        };
        let from = || {
            ArgSpec::new("from")
                .summary("the configured store the secret is copied from")
                .class(XSD_STRING)
        };
        let name = || {
            ArgSpec::new("name")
                .summary("the secret's name (or pipe it in as `content`)")
                .class(XSD_STRING)
                .optional()
        };
        let content = || {
            ArgSpec::new("content")
                .summary("the secret's name, piped in, instead of `name=`")
                .class(XSD_STRING)
                .optional()
        };
        let replace = || {
            ArgSpec::new("replace")
                .summary("`true` to replace a different value the store `{to}` already holds")
                .class(XSD_BOOLEAN)
                .one_of(["true", "false"])
                .default_value("false")
                .optional()
        };
        Description::new("secret-store-copy")
            .summary(
                "Copy one secret from the store `from` into the store `{to}`, never deleting the \
                 source: how an install moves its secrets into a new store (an age-file store, \
                 a fnox store) after adding a [secret] section. Requires the name's read scope \
                 `urn:cap:secret:read:<name>` AND its write scope `urn:cap:secret:write:<name>`, \
                 then asks for presence (macOS Touch ID). Refused into a read-only store, from a \
                 store that does not hold the name (NotFound), and into a store that already \
                 holds a different value unless `replace=true`. Answers one sentence and never a \
                 value; never cached.",
            )
            .input(to())
            .input(from())
            .input(name())
            .input(content())
            .input(replace())
            .output("text/plain")
            .action(
                ActionSpec::new(Verb::Sink)
                    .summary("copy one secret from another store into this one")
                    .requires("urn:cap:secret:read:*")
                    .requires("urn:cap:secret:write:*")
                    .input(to())
                    .input(from())
                    .input(name())
                    .input(content())
                    .input(replace())
                    .group(InputGroup::exactly_one(["name", "content"]).pipe("content"))
                    .output("text/plain"),
            )
    }
}
