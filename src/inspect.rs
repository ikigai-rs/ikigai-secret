//! The inspection resources of the routed space (`docs/storage-backends.md`, section 4):
//! compositions over the checked configuration a [`RoutingBackend`] holds. They hold no state
//! of their own and never ask a store for a secret; only one store's health line asks its
//! backend anything, and that never reads a secret.
//!
//! Every face is `text/plain` by default and `application/json` with `as=application/json`.
//! None ever carries a path, an account, a token or a value.

use std::sync::Arc;

use async_trait::async_trait;
use ikigai_core::{
    ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, ReprType,
    Representation, Result, UriTemplate, Verb,
};
use serde_json::{json, Value};

use crate::store::{RoutingBackend, StoreSpec};
use crate::{refuse_deny_shaped, XSD_STRING};

/// `urn:secret:store`: every configured store.
pub const STORE_IRI: &str = "urn:secret:store";
/// `urn:secret:store:name:{store}`: one store, with a health line.
pub const STORE_NAME_TEMPLATE: &str = "urn:secret:store:name:{store}";
/// `urn:secret:route`: the ordered routes and the default.
pub const ROUTE_IRI: &str = "urn:secret:route";
/// `urn:secret:route:secret:{name}`: the store one secret name routes to.
pub const ROUTE_SECRET_TEMPLATE: &str = "urn:secret:route:secret:{name}";
/// The scope `urn:secret:store`, `urn:secret:store:name:{store}` and `urn:secret:route` require.
/// `urn:secret:route:secret:{name}` takes the name's own read scope instead.
pub const INSPECT_SCOPE: &str = "urn:cap:secret:inspect";

const TEXT: &str = "text/plain";
const JSON: &str = "application/json";

/// Bind the four inspection resources into `space`, ahead of whatever is bound after them.
pub(crate) fn bind(space: EndpointSpace, routing: Arc<RoutingBackend>) -> EndpointSpace {
    let endpoint = |which| Inspect {
        routing: Arc::clone(&routing),
        which,
    };
    space
        .bind(Exact::new(STORE_IRI), endpoint(Which::Stores))
        .bind(
            UriTemplate::parse(STORE_NAME_TEMPLATE).expect("valid template"),
            endpoint(Which::Store),
        )
        .bind(Exact::new(ROUTE_IRI), endpoint(Which::Routes))
        .bind(
            UriTemplate::parse(ROUTE_SECRET_TEMPLATE).expect("valid template"),
            endpoint(Which::RouteFor),
        )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Which {
    Stores,
    Store,
    Routes,
    RouteFor,
}

struct Inspect {
    routing: Arc<RoutingBackend>,
    which: Which,
}

/// The face a request asks for with `as`: text by default.
fn face(inv: &Invocation<'_>) -> Result<&'static str> {
    if !inv.request.args.contains_key("as") {
        return Ok(TEXT);
    }
    match inv.inline_str("as")? {
        TEXT => Ok(TEXT),
        JSON => Ok(JSON),
        other => Err(Error::InvalidArgument {
            name: "as".into(),
            detail: format!("`{other}` is not a face of this resource; use {TEXT} or {JSON}"),
        }),
    }
}

fn answer(face: &str, text: String, json: Value) -> Representation {
    let bytes = if face == JSON {
        json.to_string().into_bytes()
    } else {
        text.into_bytes()
    };
    Representation::new(ReprType::new(face), bytes)
}

/// Whether a store can be written, in words.
fn write_words(store: &StoreSpec) -> &'static str {
    if store.read_only() {
        "read-only"
    } else if store.writable() {
        "writable"
    } else {
        "not writable"
    }
}

impl Inspect {
    fn stores_line(&self, store: &StoreSpec) -> String {
        let default = if store.name() == self.routing.config().default_store() {
            ", the default"
        } else {
            ""
        };
        format!(
            "{}: a {} store{default}, {}. {}",
            store.name(),
            store.kind().name(),
            write_words(store),
            store.kind().about()
        )
    }

    fn store_json(&self, store: &StoreSpec) -> Value {
        json!({
            "name": store.name(),
            "kind": store.kind().name(),
            "default": store.name() == self.routing.config().default_store(),
            "writable": store.writable(),
            "read_only": store.read_only(),
            "about": store.kind().about(),
        })
    }

    fn require_inspect(&self, inv: &Invocation<'_>, what: &str) -> Result<()> {
        if inv.capability.allows(INSPECT_SCOPE) {
            Ok(())
        } else {
            Err(Error::Denied(
                format!("reading {what} requires `{INSPECT_SCOPE}`").into(),
            ))
        }
    }
}

#[async_trait]
impl Endpoint for Inspect {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if inv.request.verb != Verb::Source {
            return Err(Error::Endpoint(format!(
                "{} is read with Source only",
                match self.which {
                    Which::Stores => STORE_IRI,
                    Which::Store => STORE_NAME_TEMPLATE,
                    Which::Routes => ROUTE_IRI,
                    Which::RouteFor => ROUTE_SECRET_TEMPLATE,
                }
            )));
        }
        let config = self.routing.config();
        match self.which {
            Which::Stores => {
                self.require_inspect(inv, "the configured stores")?;
                let face = face(inv)?;
                let text: Vec<String> = config
                    .stores()
                    .iter()
                    .map(|store| self.stores_line(store))
                    .collect();
                let json = json!({
                    "default": config.default_store(),
                    "stores": config.stores().iter().map(|s| self.store_json(s)).collect::<Vec<_>>(),
                });
                // A pure function of the configuration, read once at start: cacheable, and hung
                // from the configuration's thread so a reload drops it.
                Ok(answer(face, text.join("\n") + "\n", json)
                    .cacheable()
                    .depends_on(crate::CONFIG_THREAD))
            }
            Which::Store => {
                let name = inv
                    .bindings
                    .get("store")
                    .map(|s| s.to_string())
                    .ok_or_else(|| Error::MissingArgument("store".into()))?;
                self.require_inspect(inv, "a configured store")?;
                let face = face(inv)?;
                let store = config.store(&name).ok_or_else(|| {
                    Error::NotFound(format!("no store named `{name}` is configured"))
                })?;
                let backend = self
                    .routing
                    .backend(store.name())
                    .expect("every configured store has a backend");
                let health = backend.health();
                let mut json = self.store_json(store);
                json["health"] = Value::String(health.clone());
                // The health line is read now, so this answer is never cached.
                Ok(answer(
                    face,
                    format!("{}\nhealth: {health}\n", self.stores_line(store)),
                    json,
                ))
            }
            Which::Routes => {
                self.require_inspect(inv, "the routes")?;
                let face = face(inv)?;
                let mut text: Vec<String> = config
                    .routes()
                    .iter()
                    .enumerate()
                    .map(|(index, route)| {
                        format!(
                            "route {}: names matching {} go to {}.",
                            index + 1,
                            route.pattern(),
                            route.store()
                        )
                    })
                    .collect();
                if text.is_empty() {
                    text.push("No routes are configured.".into());
                    text.push(format!(
                        "default: every name goes to {}.",
                        config.default_store()
                    ));
                } else {
                    text.push(format!(
                        "default: every other name goes to {}.",
                        config.default_store()
                    ));
                }
                let json = json!({
                    "routes": config.routes().iter().enumerate().map(|(index, route)| json!({
                        "number": index + 1,
                        "match": route.pattern(),
                        "store": route.store(),
                    })).collect::<Vec<_>>(),
                    "default": config.default_store(),
                });
                Ok(answer(face, text.join("\n") + "\n", json)
                    .cacheable()
                    .depends_on(crate::CONFIG_THREAD))
            }
            Which::RouteFor => {
                let name = inv
                    .bindings
                    .get("name")
                    .map(|s| s.to_string())
                    .ok_or_else(|| Error::MissingArgument("name".into()))?;
                refuse_deny_shaped(&name, "name")?;
                // The name's own read scope: whoever may read the secret may know where it
                // lives, and nobody else. The kernel enforced the declared wildcard floor.
                let scope = format!("urn:cap:secret:read:{name}");
                if !inv.capability.allows(&scope) {
                    return Err(Error::Denied(
                        format!("asking where `{name}` lives requires `{scope}`").into(),
                    ));
                }
                let face = face(inv)?;
                // From the route table alone: no store is asked, so the answer is the same
                // whether or not a secret by this name exists.
                let routed = config.route_for(&name);
                let json = json!({
                    "name": name,
                    "store": routed.store,
                    "route": routed.route,
                });
                Ok(answer(face, format!("{}\n", routed.store), json)
                    .cacheable()
                    .depends_on(crate::CONFIG_THREAD))
            }
        }
    }

    fn name(&self) -> &str {
        match self.which {
            Which::Stores => "secret-store",
            Which::Store => "secret-store-name",
            Which::Routes => "secret-route",
            Which::RouteFor => "secret-route-secret",
        }
    }

    fn describe(&self) -> Description {
        let face_arg = || {
            ArgSpec::new("as")
                .summary("the face: `text/plain` (the default), or `application/json`")
                .class(XSD_STRING)
                .one_of([TEXT, JSON])
                .default_value(TEXT)
                .optional()
        };
        let (summary, requires, binding) = match self.which {
            Which::Stores => (
                "The configured secret stores: each one's name, kind, whether it can be \
                 written, and a sentence on what it is. Never a path, an account, a token or a \
                 value. Requires `urn:cap:secret:inspect`. Cached until the configuration is \
                 reloaded.",
                INSPECT_SCOPE,
                None,
            ),
            Which::Store => (
                "One configured secret store, by name: its kind, whether it can be written, a \
                 sentence on what it is, and a health line read now (whether it can be \
                 reached). Never a path, an account, a token or a value. Requires \
                 `urn:cap:secret:inspect`. Never cached.",
                INSPECT_SCOPE,
                Some(
                    ArgSpec::new("store")
                        .summary("the store's name (the `{store}` URI slot)")
                        .class(XSD_STRING)
                        .binding(),
                ),
            ),
            Which::Routes => (
                "The secret routes, in the order they are read (the first match wins), and the \
                 default store that takes every name no route matches. Requires \
                 `urn:cap:secret:inspect`. Cached until the configuration is reloaded.",
                INSPECT_SCOPE,
                None,
            ),
            Which::RouteFor => (
                "The store one secret name routes to, from the route table alone: no store is \
                 asked, so the answer says nothing about whether the secret exists. Requires \
                 the name's own read scope, `urn:cap:secret:read:<name>`. Cached until the \
                 configuration is reloaded.",
                "urn:cap:secret:read:*",
                Some(
                    ArgSpec::new("name")
                        .summary("the secret's name (the `{name}` URI slot)")
                        .class(XSD_STRING)
                        .binding(),
                ),
            ),
        };
        // One verb, authored flat (the module recipe's common case).
        let mut description = Description::new(self.name())
            .summary(summary)
            .verb(Verb::Source)
            .requires(requires);
        if let Some(binding) = binding {
            description = description.input(binding);
        }
        description.input(face_arg()).output(TEXT).output(JSON)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_inspection_endpoint_has_one_name() {
        let routing = Arc::new(
            crate::SecretConfig::from_section(None, None)
                .unwrap()
                .build(),
        );
        for which in [Which::Stores, Which::Store, Which::Routes, Which::RouteFor] {
            let endpoint = Inspect {
                routing: routing.clone(),
                which,
            };
            assert_eq!(endpoint.name(), endpoint.describe().id);
        }
    }
}
