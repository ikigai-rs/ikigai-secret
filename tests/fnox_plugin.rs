//! The fnox Lua plugin, `contrib/fnox/ikigai.lua` (ledger #4492).
//!
//! ## Which test this is
//!
//! **A test of the exact command line the plugin builds, not a run through fnox.** fnox is not
//! installed on CI's runners (nor on the machine this was written on), and neither is a kernel
//! host with a secret to read. So the plugin is loaded into Lua 5.4 (mlua, vendored, the
//! version fnox's plugins target) beside a stand-in for `fnox.cmd` that records each command it
//! is asked to run and answers what `ikigai` answers: the value followed by one newline and exit
//! 0, or a sentence on standard error and exit 1. The shapes of those answers were read from the
//! `ikigai` 0.5.3 command (`println!` of the answer; `error: not found: …` and `error: denied:
//! …` on standard error), so a change there is a change this test has to follow.
//!
//! What it pins: the argument list, exactly; no shell; an empty standard input; the one
//! trailing newline removed and nothing else; NotFound as `nil` (so fnox's `if_missing` applies);
//! every other failure as an error carrying ikigai's sentence; and a name that ikigai's command
//! grammar would read as more than a name refused before any command runs.

use mlua::{Function, Lua, Table, Value};

const PLUGIN: &str = include_str!("../contrib/fnox/ikigai.lua");

/// One scripted answer from the stand-in `ikigai`: (exit status, stdout, stderr).
type Answer = (i64, &'static str, &'static str);

/// A Lua state with a stand-in `fnox.cmd` that answers `answer` and records every call in the
/// global `calls`, and the plugin's hook table.
fn plugin(answer: Answer) -> (Lua, Table) {
    let lua = Lua::new();
    let (status, stdout, stderr) = answer;
    lua.globals()
        .set("calls", lua.create_table().unwrap())
        .unwrap();
    let stand_in = format!(
        r#"
        package.preload["fnox.cmd"] = function()
          local function record(command, opts)
            calls[#calls + 1] = {{ command = command, opts = opts }}
          end
          return {{
            run = function(command, opts)
              record(command, opts)
              return {{ status = {status}, ok = {ok}, stdout = {stdout:?}, stderr = {stderr:?} }}
            end,
            exec = function(command, opts)
              record(command, opts)
              error("the plugin must not use exec: it raises without the stderr sentence")
            end,
          }}
        end
        "#,
        ok = status == 0,
    );
    lua.load(stand_in).exec().unwrap();
    let hooks: Table = lua.load(PLUGIN).set_name("ikigai.lua").eval().unwrap();
    (lua, hooks)
}

fn ctx(lua: &Lua, options: &[(&str, &str)]) -> Table {
    let ctx = lua.create_table().unwrap();
    let opts = lua.create_table().unwrap();
    for (key, value) in options {
        opts.set(*key, *value).unwrap();
    }
    ctx.set("provider", "ikigai").unwrap();
    ctx.set("options", opts).unwrap();
    ctx
}

/// The recorded calls: each command as its argument list, and its standard input.
fn calls(lua: &Lua) -> Vec<(Vec<String>, Option<String>)> {
    let calls: Table = lua.globals().get("calls").unwrap();
    calls
        .sequence_values::<Table>()
        .map(|call| {
            let call = call.unwrap();
            let command: Table = call.get("command").unwrap();
            let argv = command
                .sequence_values::<String>()
                .map(Result::unwrap)
                .collect();
            let opts: Option<Table> = call.get("opts").unwrap();
            let stdin = opts.and_then(|o| o.get::<Option<String>>("stdin").unwrap());
            (argv, stdin)
        })
        .collect()
}

fn get(lua: &Lua, hooks: &Table, options: &[(&str, &str)], name: &str) -> mlua::Result<Value> {
    let get: Function = hooks.get("get").unwrap();
    get.call((ctx(lua, options), name))
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

#[test]
fn get_runs_exactly_one_ikigai_source_with_an_empty_stdin() {
    let (lua, hooks) = plugin((0, "s3cret\n", "[computed]\n"));
    let value = get(&lua, &hooks, &[], "zoom.client-secret").unwrap();
    assert_eq!(value.as_string().unwrap().to_str().unwrap(), "s3cret");
    assert_eq!(
        calls(&lua),
        [(
            argv(&[
                "ikigai",
                "--quiet",
                "-c",
                "source urn:secret:zoom.client-secret"
            ]),
            Some(String::new())
        )]
    );
}

#[test]
fn the_options_choose_the_binary_and_the_host() {
    let (lua, hooks) = plugin((0, "v\n", ""));
    get(
        &lua,
        &hooks,
        &[
            ("command", "/opt/ikigai/bin/ikigai"),
            ("connect", "/run/ikigai/kernel.sock"),
        ],
        "owner:id:acme:name:db",
    )
    .unwrap();
    assert_eq!(
        calls(&lua)[0].0,
        argv(&[
            "/opt/ikigai/bin/ikigai",
            "--quiet",
            "--connect",
            "/run/ikigai/kernel.sock",
            "-c",
            "source urn:secret:owner:id:acme:name:db"
        ])
    );
}

#[test]
fn only_the_one_newline_ikigai_adds_is_removed() {
    for (stdout, expected) in [
        ("value\n", "value"),
        ("value\n\n", "value\n"),
        ("two\nlines\n", "two\nlines"),
        ("no newline", "no newline"),
        ("\n", ""),
    ] {
        let (lua, hooks) = plugin((0, stdout, ""));
        let value = get(&lua, &hooks, &[], "a").unwrap();
        assert_eq!(
            value.as_string().unwrap().to_str().unwrap(),
            expected,
            "{stdout:?}"
        );
    }
}

#[test]
fn not_found_is_nil_so_fnox_if_missing_applies() {
    let (lua, hooks) = plugin((1, "", "error: not found: no secret `zoom.x`\n"));
    assert!(matches!(
        get(&lua, &hooks, &[], "zoom.x").unwrap(),
        Value::Nil
    ));
}

#[test]
fn a_refusal_is_an_error_in_ikigais_words() {
    let denied = "error: denied: reading `zoom.x` requires `urn:cap:secret:read:zoom.x`";
    for (stderr, expected) in [
        (
            denied,
            format!("ikigai refused urn:secret:zoom.x: {denied}"),
        ),
        (
            "ikigai: connect /run/k.sock: No such file or directory (os error 2)\n",
            "ikigai refused urn:secret:zoom.x: ikigai: connect /run/k.sock: No such file or \
             directory (os error 2)"
                .to_string(),
        ),
        (
            "",
            "ikigai refused urn:secret:zoom.x: exit status 1".to_string(),
        ),
    ] {
        let (lua, hooks) = plugin((1, "", stderr));
        let err = get(&lua, &hooks, &[], "zoom.x").unwrap_err();
        assert!(err.to_string().contains(&expected), "{stderr:?}: {err}");
    }
}

#[test]
fn a_name_the_command_grammar_would_split_is_refused_before_any_command() {
    for name in [
        "",
        "two words",
        "it's",
        "a=b",
        "a|b",
        "a\"b",
        "-leading",
        "caf\u{e9}",
        "a\nb",
    ] {
        let (lua, hooks) = plugin((0, "never\n", ""));
        let err = get(&lua, &hooks, &[], name).unwrap_err();
        assert!(err.to_string().contains("ikigai: "), "{name:?}: {err}");
        assert!(calls(&lua).is_empty(), "{name:?} ran a command");
    }
}

#[test]
fn the_plugin_is_get_only_and_every_hook_is_a_function() {
    let (_lua, hooks) = plugin((0, "", ""));
    let mut keys: Vec<String> = hooks
        .pairs::<String, Value>()
        .map(|pair| {
            let (key, value) = pair.unwrap();
            assert!(matches!(value, Value::Function(_)), "{key} is a function");
            key
        })
        .collect();
    keys.sort();
    assert_eq!(keys, ["get"]);
}
