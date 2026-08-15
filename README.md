# mcpg-expr

> The CEL-backed dynamic-value engine shared by the MCPG gateway and its backend plugins.

`mcpg-expr` turns an operator-supplied configuration string containing `${...}`
interpolation markers into a value that can be resolved per request. Parsing and
CEL compilation happen once, when a binding is registered; evaluation happens on
the request path against a standard variable bag. A string with no `${` marker is
recognised as a literal and costs nothing at request time. The crate is
deliberately narrow: it is not a policy engine, not a general template renderer,
and it never resolves a credential reference itself — the caller supplies that
value through a callback. It exists so that every component of the
gateway — and every backend plugin that hosts operator templates — resolves the
same expression the same way, with the same variables and the same
credential-reference rules.

## What's here

- `DynamicValue<String>` — `parse()` classifies a config string as `Literal`, a
  single compiled CEL `Expression`, or a `Composite` of ordered segments;
  `resolve()` evaluates it; `resolve_with_credentials()` additionally supplies
  values for `cred://` segments; `cred_refs()` lists the credential URIs a value
  references.
- `CompositeSegment` — `Literal(String)`, `Cel { source, program }`, and
  `Cred(String)` (the verbatim `cred://issuer/target` URI, scheme included).
- `ExprContext` — the standard variable bag: `arguments`, `tool_name`, `context`,
  `steps`, `env`. `to_cel_context()` binds them all into a `cel::Context`.
- `ExprRequestContext` — the request fields exposed to expressions:
  `principal_id`, `trust_level`, `auth_provider`, `session_id`, `transport`,
  `roles`, `groups`, `scopes`, `attributes`.
- `resolve_env_in_string()` — the config-load pass. It substitutes `${env.VAR}`,
  errors on an unset variable, and leaves every other `${...}` form untouched for
  the request-time layers.
- `json_to_cel()` / `cel_value_to_json()` — conversion between
  `serde_json::Value` and `cel::Value`.
- `validate_header_name()` / `validate_header_value()` — an RFC 7230 token check
  plus CR/LF rejection, so a resolved value cannot inject a header.

Variables are written bare inside the markers — `${arguments.x}`, `${env.X}`. A
`$`-prefixed spelling inside the braces is not accepted.

| Variable | Phase | Type | Contents |
|---|---|---|---|
| `arguments` | request | map | Tool-call arguments. Also bound as `args`. |
| `tool_name` | request | string | The tool being invoked. |
| `context.*` | request | map | `principal_id`, `trust_level`, `auth_provider`, `session_id`, `transport`, `roles`, `groups`, `scopes`, `attributes`. |
| `steps.<id>.output` / `steps.<id>.is_error` | pipeline | value / bool | Prior pipeline-step results; bound only while a pipeline is executing. |
| `env.<NAME>` | startup | string | Environment variables captured at config load. |

`trust_level`, `principal_id`, `auth_provider`, and `identity_kind` are also
bound as bare top-level aliases, so a flat policy-style expression evaluates
without being rewritten into the nested `context.` form.

Credential references are the security-load-bearing part of the parser.
`${cred://issuer/target}` segments are extracted from the **operator template**
at parse time, which makes them config-origin by construction: a request argument
substituted into a neighbouring CEL segment is only ever a value and can never
introduce a new credential reference. A `Composite` value refuses plain
`resolve()` and must go through `resolve_with_credentials()`, whose resolver
callback is keyed by the verbatim URI.

## Used by

- `apps/gateway` — request-time resolution of binding config, pipeline step
  inputs, and header templates.
- The net-shaped backend plugins — `libs/plugins/backend/net-core` and the
  `http`, `soap`, `command`, and `ldap` backends — for per-call URL, header, and
  argument resolution, so a cdylib compiles operator CEL exactly the way the
  gateway does.

## Usage

```toml
[dependencies]
mcpg-expr = "<version>"
serde_json = "1"
```

```rust
use mcpg_expr::{DynamicValue, ExprContext, ExprRequestContext};

// Compiled once, at registration time.
let url = DynamicValue::parse(
    "https://api.example.com/v1/users/${arguments.user_id}",
)?;

// Rebuilt per request.
let ctx = ExprContext {
    arguments: serde_json::json!({ "user_id": "u-42" }),
    tool_name: "get_user".to_owned(),
    context: ExprRequestContext {
        trust_level: "verified".to_owned(),
        ..Default::default()
    },
    ..Default::default()
};

assert_eq!(url.resolve(&ctx)?, "https://api.example.com/v1/users/u-42");
```

A value carrying a credential reference resolves through a callback instead:

```rust
use mcpg_expr::{DynamicValue, ExprContext};

let header = DynamicValue::parse("Bearer ${cred://my-issuer/orders}")?;
assert_eq!(header.cred_refs(), vec!["cred://my-issuer/orders"]);

let resolved = header.resolve_with_credentials(&ExprContext::default(), |uri| {
    (uri == "cred://my-issuer/orders").then(|| "opaque-token".to_owned())
})?;
assert_eq!(resolved, "Bearer opaque-token");
```

## Build / test

```bash
cargo build -p mcpg-expr
cargo test  -p mcpg-expr
```

## Licence

Apache-2.0.

## See also

- [Gateway configuration reference](https://mcpg.dev/docs/reference/configuration) — where these expressions and `cred://` URIs appear in a real config.
- [Pipeline steps](https://mcpg.dev/docs/reference/pipeline-steps) — the multi-step surface that populates `steps.*`.
- `libs/plugins/backend/net-core` — the shared backend core that compiles operator templates through this crate.
