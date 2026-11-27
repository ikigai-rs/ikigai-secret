-- ikigai as a fnox provider (ledger #4492; docs/storage-backends.md, section 7).
--
-- A fnox Lua 5.4 provider plugin. `get` resolves a fnox secret through ikigai: it runs
--
--     ikigai --quiet [--connect <target>] -c 'source urn:secret:<ref>'
--
-- so the read goes through ikigai's per-name capabilities, its presence gate and its audit, in
-- whatever host the `ikigai` command reaches. The plugin grants nothing: the capability is
-- whatever that command's identity holds. It never reads a store itself.
--
-- Options (`options = { ... }` in fnox.toml, all optional, all strings):
--   command  the ikigai binary to run (default "ikigai", found on PATH)
--   connect  a kernel server to attach to, as `ikigai --connect` takes it: a Unix socket path or
--            quic://host:port. Absent, the `ikigai` command's own host answers.
--
-- `get` only. `put` waits until fnox.cmd is shown to hand a value to a command on standard input
-- without putting it in the arguments.

local cmd = require("fnox.cmd")

-- A secret name the plugin will put in a command line: ASCII letters, digits, `.`, `_`, `-` and
-- `:` (owner-keyed names such as owner:id:acme:name:db), never beginning with `-`. Anything else
-- (a space, a quote, `=`, `|`) would be read by ikigai's command grammar as more than a name, so
-- it is refused before any command runs.
local function check_ref(ref)
  if type(ref) ~= "string" or ref == "" then
    error("ikigai: a secret reference must be a non-empty secret name", 0)
  end
  if not ref:match("^[A-Za-z0-9._:-]+$") then
    error("ikigai: `" .. ref .. "` is not a secret name this plugin passes on: use ASCII " ..
      "letters, digits, `.`, `_`, `-` and `:` only", 0)
  end
  if ref:sub(1, 1) == "-" then
    error("ikigai: `" .. ref .. "` begins with `-`, which no ikigai secret name may", 0)
  end
end

-- The exact argument list `get` runs for `ref`. No shell is involved: fnox.cmd runs an argument
-- table directly.
local function argv(ctx, ref)
  local options = (ctx and ctx.options) or {}
  local args = { options.command or "ikigai", "--quiet" }
  if options.connect and options.connect ~= "" then
    args[#args + 1] = "--connect"
    args[#args + 1] = options.connect
  end
  args[#args + 1] = "-c"
  args[#args + 1] = "source urn:secret:" .. ref
  return args
end

-- The first line of what ikigai wrote on standard error, without its trailing newline.
local function first_line(text)
  return ((text or ""):match("^[^\n]*") or "")
end

return {
  get = function(ctx, ref)
    check_ref(ref)
    -- An empty standard input: nothing in the batch reads it, and an idle terminal must never be
    -- mistaken for a value.
    local result = cmd.run(argv(ctx, ref), { stdin = "" })
    if result.ok then
      -- `ikigai -c` prints an answer followed by one newline; that newline is not the secret's.
      local value = result.stdout or ""
      if value:sub(-1) == "\n" then
        value = value:sub(1, -2)
      end
      return value
    end
    local why = first_line(result.stderr)
    -- ikigai's NotFound: no secret by that name in the store it routes to. fnox's `if_missing`
    -- and `default` then apply.
    if why:match("^error: not found:") then
      return nil
    end
    -- Anything else is a refusal or a failure, reported in ikigai's own words. ikigai's error
    -- sentences never carry a secret's value.
    if why == "" then
      why = "exit status " .. tostring(result.status)
    end
    error("ikigai refused urn:secret:" .. ref .. ": " .. why, 0)
  end,
}
