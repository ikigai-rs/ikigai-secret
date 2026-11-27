//! fnox's own rule, not this crate's: a declared key with neither a provider value nor a default
//! falls back to the environment variable OF THE SAME NAME. Pinned so a change in fnox is
//! noticed; the README and the crate docs warn a host operator about it.
//!
//! A test binary of its own, because it sets a process environment variable, which no other
//! thread may be reading while it does.

use std::path::Path;

use ikigai_secret::{Backend, SecretConfig, SecretSection};
use ikigai_secret_fnox::FnoxStore;

#[test]
fn a_declared_key_with_no_value_reads_the_hosts_environment() {
    let dir = tempfile::tempdir().unwrap();
    let key = "IKIGAI_SECRET_FNOX_TEST_ENV_FALLBACK";
    let path = dir.path().join("fnox.toml");
    std::fs::write(
        &path,
        format!("[secrets]\n{key} = {{ if_missing = \"ignore\" }}\n"),
    )
    .unwrap();
    let section: SecretSection = toml::from_str(&format!(
        "default = \"team\"\n[store.team]\nkind = \"fnox\"\nconfig = {:?}\n[store.team.map]\n\
         \"fallback\" = \"{key}\"\n",
        path.display().to_string()
    ))
    .unwrap();
    let config = SecretConfig::from_section(Some(&section), Some(Path::new("/home/svc"))).unwrap();
    let store = FnoxStore::open(&config.stores()[0]).unwrap();
    assert_eq!(store.get("fallback").unwrap(), None);
    std::env::set_var(key, "from-the-environment");
    let read_back = store.get("fallback");
    std::env::remove_var(key);
    assert_eq!(
        read_back.unwrap().as_deref(),
        Some(&b"from-the-environment"[..])
    );
}
