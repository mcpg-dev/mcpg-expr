//! Unified expression engine for dynamic configuration values.
//!
//! Provides two resolution phases:
//! 1. **Startup** — `${env.VAR_NAME}` references are resolved immediately when config loads.
//! 2. **Request-time** — Expressions containing `arguments`, `tool_name`, `context`, `steps`
//!    are evaluated per-call via CEL.
//!
//! A string field is treated as an expression if it contains `${...}` interpolation markers.
//! Plain strings pass through with zero overhead.
//!
//! Variable references are written bare (`${env.X}`, `${arguments.x}`). A
//! `$`-prefixed spelling is not accepted — `${env.X}` (not `${$env.X}`),
//! `${arguments.x}` (not `${$arguments.x}`).
//!
//! # Standard Variable Registry
//!
//! | Variable | Phase | Type | Description |
//! |---|---|---|---|
//! | `arguments` | Request | Map | Tool call arguments |
//! | `tool_name` | Request | String | Tool name |
//! | `context.principal_id` | Request | String? | Authenticated principal |
//! | `context.trust_level` | Request | String | Trust level |
//! | `context.auth_provider` | Request | String? | Identity provider |
//! | `context.session_id` | Request | String? | Session ID |
//! | `context.transport` | Request | String | Transport kind |
//! | `env.VAR` | Startup | String | Environment variable |
//! | `steps.ID.output` | Pipeline | Value | Step result |
//! | `steps.ID.is_error` | Pipeline | Bool | Step error flag |
//!
//! Outbound credentials (e.g. OAuth bearer tokens) are NOT a CEL
//! root. Bindings reference them via the `cred://<plugin_id>/<target>`
//! URI scheme, which is resolved per-request by the
//! gateway's credential resolver before the binding sees its config.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context as AnyhowContext, Result};
use cel::{
    Context as CelContext, Program, Value as CelValue,
    objects::{Key as CelKey, Map as CelMap},
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// DynamicValue — the core abstraction
// ---------------------------------------------------------------------------

/// A configuration value that may be a literal, a compiled CEL
/// expression, or a composite of literal / CEL / `cred://` segments.
#[derive(Debug)]
pub enum DynamicValue<T: std::fmt::Debug> {
    /// A plain literal value (no `${...}` markers found).
    Literal(T),
    /// A single CEL interpolation (no `${cred://...}` references).
    Expression {
        /// Original source string for logging/diagnostics.
        source: String,
        /// Compiled CEL program.
        program: Program,
    },
    /// A template carrying one or more `${cred://issuer/target}`
    /// credential references, split into ordered segments.
    ///
    /// SECURITY: credential refs are parsed from the OPERATOR TEMPLATE
    /// here, at compile time, so they are config-origin **by
    /// construction** — a request argument substituted into a CEL
    /// segment is just a value and can never introduce a new credential
    /// reference. Resolve via [`Self::resolve_with_credentials`].
    Composite {
        /// Original source string for logging/diagnostics.
        source: String,
        /// Ordered literal / CEL / credential pieces.
        segments: Vec<CompositeSegment>,
    },
}

/// One ordered piece of a [`DynamicValue::Composite`].
#[derive(Debug)]
pub enum CompositeSegment {
    /// Verbatim literal text.
    Literal(String),
    /// A `${expr}` CEL block, compiled.
    Cel {
        /// Original expression source.
        source: String,
        /// Compiled CEL program.
        program: Program,
    },
    /// A `${cred://issuer/target}` reference — the inner URI verbatim
    /// (including the `cred://` scheme). The host resolves it per caller
    /// identity at request time.
    Cred(String),
}

impl DynamicValue<String> {
    /// Parse a string, detecting `${...}` markers.
    ///
    /// - No `${` marker → [`Self::Literal`].
    /// - Contains a `${cred://…}` reference → [`Self::Composite`].
    /// - Otherwise → [`Self::Expression`] (one compiled CEL program).
    ///
    /// Variable refs are written bare (`${arguments.x}`); a `$`-prefix is
    /// not accepted.
    pub fn parse(input: &str) -> Result<Self> {
        if !input.contains("${") {
            return Ok(DynamicValue::Literal(input.to_owned()));
        }

        let segments = parse_segments(input)?;
        if segments
            .iter()
            .any(|s| matches!(s, CompositeSegment::Cred(_)))
        {
            return Ok(DynamicValue::Composite {
                source: input.to_owned(),
                segments,
            });
        }

        // No credential refs — compile the whole template into a single
        // CEL program (unchanged fast path).
        let cel_source = interpolation_to_cel(input)?;
        let program = Program::compile(&cel_source)
            .map_err(|e| anyhow::anyhow!("failed to compile expression: {}", e))
            .with_context(|| format!("expression source: {}", input))?;

        Ok(DynamicValue::Expression {
            source: input.to_owned(),
            program,
        })
    }

    /// Resolve this value against an expression context.
    ///
    /// Literals are returned as-is; expressions are evaluated via CEL.
    /// Errors on a [`Self::Composite`] (it carries `${cred://…}` refs —
    /// use [`Self::resolve_with_credentials`]).
    pub fn resolve(&self, ctx: &ExprContext) -> Result<String> {
        match self {
            DynamicValue::Literal(s) => Ok(s.clone()),
            DynamicValue::Expression { source, program } => eval_program(program, source, ctx),
            DynamicValue::Composite { source, .. } => Err(anyhow::anyhow!(
                "value carries ${{cred://…}} reference(s); resolve it via \
                 resolve_with_credentials: {source}"
            )),
        }
    }

    /// The `cred://…` URIs this value references, parsed from the
    /// operator template (config-origin). Empty for non-composite values.
    pub fn cred_refs(&self) -> Vec<&str> {
        match self {
            DynamicValue::Composite { segments, .. } => segments
                .iter()
                .filter_map(|s| match s {
                    CompositeSegment::Cred(uri) => Some(uri.as_str()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Resolve, supplying resolved values for any `${cred://…}` refs via
    /// `resolve_cred` (keyed by the verbatim `cred://…` URI). Literal and
    /// expression values never call `resolve_cred`.
    pub fn resolve_with_credentials<F>(&self, ctx: &ExprContext, resolve_cred: F) -> Result<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        match self {
            DynamicValue::Literal(_) | DynamicValue::Expression { .. } => self.resolve(ctx),
            DynamicValue::Composite { segments, .. } => {
                let mut out = String::new();
                for seg in segments {
                    match seg {
                        CompositeSegment::Literal(s) => out.push_str(s),
                        CompositeSegment::Cel { source, program } => {
                            out.push_str(&eval_program(program, source, ctx)?);
                        }
                        CompositeSegment::Cred(uri) => {
                            let v = resolve_cred(uri).ok_or_else(|| {
                                anyhow::anyhow!("unresolved credential reference: {uri}")
                            })?;
                            out.push_str(&v);
                        }
                    }
                }
                Ok(out)
            }
        }
    }
}

/// Evaluate a compiled CEL program against `ctx`, stringifying the result.
fn eval_program(program: &Program, source: &str, ctx: &ExprContext) -> Result<String> {
    let cel_ctx = ctx.to_cel_context()?;
    let result = program
        .execute(&cel_ctx)
        .map_err(|e| anyhow::anyhow!("expression evaluation failed: {}", e))
        .with_context(|| format!("expression: {}", source))?;
    cel_value_to_string(&result).with_context(|| format!("expression: {}", source))
}

// ---------------------------------------------------------------------------
// ExprContext — the standardized variable bag
// ---------------------------------------------------------------------------

/// Context for expression evaluation.
///
/// Carries all standard variables available to CEL expressions.
/// Built once per request from `RequestContext` + `ToolCallParams`.
#[derive(Debug, Clone, Default)]
pub struct ExprContext {
    /// Tool call arguments (`$arguments`).
    pub arguments: Value,
    /// Tool name (`$tool_name`).
    pub tool_name: String,
    /// Request context fields (`$context.*`).
    pub context: ExprRequestContext,
    /// Pipeline step results (`$steps.*`) — only populated during pipeline execution.
    pub steps: Option<Value>,
    /// Resolved environment variables (`$env.*`) — populated at startup.
    pub env: Arc<HashMap<String, String>>,
}

/// Request context subset exposed to expressions.
#[derive(Debug, Clone, Default)]
pub struct ExprRequestContext {
    pub principal_id: Option<String>,
    pub trust_level: String,
    pub auth_provider: Option<String>,
    pub session_id: Option<String>,
    pub transport: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub attributes: std::collections::BTreeMap<String, String>,
}

impl ExprContext {
    /// Build the `cel::Context` with all standard variables bound.
    ///
    /// Context fields are bound twice on purpose: once nested under
    /// `context.*` and once as bare top-level aliases (`trust_level`,
    /// `principal_id`, …). The nested form is the documented
    /// expression syntax; the aliases let policy-style expressions
    /// written against the flat namespace evaluate unchanged.
    pub fn to_cel_context<'a>(&'a self) -> Result<CelContext<'a>> {
        let mut ctx = CelContext::default();

        // $arguments
        let args_cel = json_to_cel(&self.arguments);
        ctx.add_variable("arguments", args_cel.clone())
            .map_err(|e| anyhow::anyhow!("failed to bind $arguments: {}", e))?;
        // Backward-compatible alias for pipeline expressions
        ctx.add_variable("args", args_cel)
            .map_err(|e| anyhow::anyhow!("failed to bind $args alias: {}", e))?;

        // $tool_name
        ctx.add_variable("tool_name", self.tool_name.as_str())
            .map_err(|e| anyhow::anyhow!("failed to bind $tool_name: {}", e))?;

        // $context as a CEL map
        let context_map = self.build_context_map();
        ctx.add_variable("context", context_map)
            .map_err(|e| anyhow::anyhow!("failed to bind $context: {}", e))?;

        // Policy-compatible top-level aliases for context fields.
        // Allows expressions like `trust_level == "verified"` (policy style)
        // in addition to `context.trust_level == "verified"` (nested style).
        ctx.add_variable("trust_level", self.context.trust_level.as_str())
            .map_err(|e| anyhow::anyhow!("failed to bind $trust_level: {}", e))?;
        ctx.add_variable("principal_id", self.context.principal_id.clone())
            .map_err(|e| anyhow::anyhow!("failed to bind $principal_id: {}", e))?;
        ctx.add_variable("auth_provider", self.context.auth_provider.clone())
            .map_err(|e| anyhow::anyhow!("failed to bind $auth_provider: {}", e))?;
        ctx.add_variable("identity_kind", self.context.transport.as_str())
            .map_err(|e| anyhow::anyhow!("failed to bind $identity_kind: {}", e))?;

        // $steps (pipeline only)
        if let Some(ref steps_value) = self.steps {
            let steps_cel = json_to_cel(steps_value);
            ctx.add_variable("steps", steps_cel)
                .map_err(|e| anyhow::anyhow!("failed to bind $steps: {}", e))?;
        }

        // $env as a CEL map
        let env_map = self.build_env_map();
        ctx.add_variable("env", env_map)
            .map_err(|e| anyhow::anyhow!("failed to bind env: {}", e))?;

        Ok(ctx)
    }

    fn build_context_map(&self) -> CelValue {
        let mut map: HashMap<CelKey, CelValue> = HashMap::new();
        map.insert(
            CelKey::String("principal_id".to_owned().into()),
            match &self.context.principal_id {
                Some(id) => CelValue::String(id.clone().into()),
                None => CelValue::Null,
            },
        );
        map.insert(
            CelKey::String("trust_level".to_owned().into()),
            CelValue::String(self.context.trust_level.clone().into()),
        );
        map.insert(
            CelKey::String("auth_provider".to_owned().into()),
            match &self.context.auth_provider {
                Some(p) => CelValue::String(p.clone().into()),
                None => CelValue::Null,
            },
        );
        map.insert(
            CelKey::String("session_id".to_owned().into()),
            match &self.context.session_id {
                Some(id) => CelValue::String(id.clone().into()),
                None => CelValue::Null,
            },
        );
        map.insert(
            CelKey::String("transport".to_owned().into()),
            CelValue::String(self.context.transport.clone().into()),
        );

        // Claim-based identity fields
        let roles_cel: Vec<CelValue> = self
            .context
            .roles
            .iter()
            .map(|r| CelValue::String(r.clone().into()))
            .collect();
        map.insert(
            CelKey::String("roles".to_owned().into()),
            CelValue::List(roles_cel.into()),
        );

        let groups_cel: Vec<CelValue> = self
            .context
            .groups
            .iter()
            .map(|g| CelValue::String(g.clone().into()))
            .collect();
        map.insert(
            CelKey::String("groups".to_owned().into()),
            CelValue::List(groups_cel.into()),
        );

        let scopes_cel: Vec<CelValue> = self
            .context
            .scopes
            .iter()
            .map(|s| CelValue::String(s.clone().into()))
            .collect();
        map.insert(
            CelKey::String("scopes".to_owned().into()),
            CelValue::List(scopes_cel.into()),
        );

        let attrs_map: HashMap<CelKey, CelValue> = self
            .context
            .attributes
            .iter()
            .map(|(k, v)| {
                (
                    CelKey::String(k.clone().into()),
                    CelValue::String(v.clone().into()),
                )
            })
            .collect();
        map.insert(
            CelKey::String("attributes".to_owned().into()),
            CelValue::Map(CelMap {
                map: Arc::new(attrs_map),
            }),
        );

        CelValue::Map(CelMap { map: Arc::new(map) })
    }

    fn build_env_map(&self) -> CelValue {
        let map: HashMap<CelKey, CelValue> = self
            .env
            .iter()
            .map(|(k, v)| {
                (
                    CelKey::String(k.clone().into()),
                    CelValue::String(v.clone().into()),
                )
            })
            .collect();
        CelValue::Map(CelMap { map: Arc::new(map) })
    }
}

// ---------------------------------------------------------------------------
// Environment variable resolution (startup phase)
// ---------------------------------------------------------------------------

/// Resolve `${env.VAR}` references in a string using real environment
/// variables.
///
/// Called at config-load time. Returns the string with every env
/// reference replaced by its value; errors on any unset variable. Other
/// `${...}` expressions (`${arguments.*}`, `${cred://…}`, …) are left
/// untouched for the request-time layers. The marker end is matched
/// nesting-aware, consistent with the CEL/cred parser.
pub fn resolve_env_in_string(input: &str) -> Result<String> {
    if !input.contains("${env.") {
        return Ok(input.to_owned());
    }

    let mut result = String::with_capacity(input.len());
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        if bytes[i..].starts_with(b"${env.") {
            // The `{` sits at i+1; find its matching `}` so a nested `${}`
            // inside the name doesn't truncate at the first brace.
            let var_start = i + "${env.".len();
            let end = find_matching_brace(input, i + 2)
                .ok_or_else(|| anyhow::anyhow!("unclosed ${{env.}} reference at position {}", i))?;
            let var_name = &input[var_start..end];
            if var_name.is_empty() {
                return Err(anyhow::anyhow!(
                    "empty env var name in ${{env.}} at position {}",
                    i
                ));
            }
            let value = std::env::var(var_name)
                .with_context(|| format!("environment variable '{}' is not set", var_name))?;
            result.push_str(&value);
            i = end + 1;
        } else {
            // Copy verbatim up to the next marker so multibyte UTF-8 in
            // surrounding text is preserved exactly.
            let next = input[i + 1..]
                .find("${env.")
                .map(|pos| i + 1 + pos)
                .unwrap_or(bytes.len());
            result.push_str(&input[i..next]);
            i = next;
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Interpolation → CEL compilation
// ---------------------------------------------------------------------------

/// Split an interpolated string into ordered [`CompositeSegment`]s,
/// recognizing `${cred://…}` (credential ref), `${expr}` (CEL), and
/// literal text. Used when a `${cred://…}` reference is present;
/// non-credential templates take the single-program path in
/// [`DynamicValue::parse`].
fn parse_segments(input: &str) -> Result<Vec<CompositeSegment>> {
    let mut segments = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let start = i + 2;
            let end = find_matching_brace(input, start)
                .ok_or_else(|| anyhow::anyhow!("unclosed ${{}} expression at position {}", i))?;
            let raw = input[start..end].trim();
            if raw.is_empty() {
                return Err(anyhow::anyhow!("empty expression at position {}", i));
            }
            if raw.starts_with("cred://") {
                // Credential URI — stored verbatim (incl. the `cred://`
                // scheme); the host resolves it per caller identity.
                segments.push(CompositeSegment::Cred(raw.to_owned()));
            } else {
                let program = Program::compile(raw)
                    .map_err(|e| anyhow::anyhow!("failed to compile expression: {}", e))
                    .with_context(|| format!("expression source: {}", raw))?;
                segments.push(CompositeSegment::Cel {
                    source: raw.to_owned(),
                    program,
                });
            }
            i = end + 1;
        } else {
            let seg_start = i;
            while i < bytes.len()
                && !(i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{')
            {
                i += 1;
            }
            segments.push(CompositeSegment::Literal(input[seg_start..i].to_owned()));
        }
    }
    Ok(segments)
}

/// Convert an interpolated string like `"hello ${arguments.name}!"` into a CEL
/// expression like `"hello " + arguments.name + "!"`.
///
/// Rules:
/// - `${expr}` blocks are extracted and treated as CEL (bare variable names —
///   `arguments`, `context`, `env`, …; a `$`-prefix is not accepted).
/// - Literal segments are wrapped in double-quotes.
/// - If the entire string is a single `${expr}`, the result is just `expr`.
fn interpolation_to_cel(input: &str) -> Result<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            // Find the closing }
            let start = i + 2;
            let end = find_matching_brace(input, start)
                .ok_or_else(|| anyhow::anyhow!("unclosed ${{}} expression at position {}", i))?;
            let raw_expr = input[start..end].trim();
            if raw_expr.is_empty() {
                return Err(anyhow::anyhow!("empty expression at position {}", i));
            }
            parts.push(raw_expr.to_owned());
            i = end + 1;
        } else {
            // Literal segment — collect until next ${
            let seg_start = i;
            while i < bytes.len()
                && !(i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{')
            {
                i += 1;
            }
            let segment = &input[seg_start..i];
            // Escape quotes for CEL string literal
            let escaped = segment.replace('\\', "\\\\").replace('"', "\\\"");
            parts.push(format!("\"{}\"", escaped));
        }
    }

    if parts.len() == 1 {
        // Single expression — return as-is (might be non-string)
        // Check if it's a literal string we wrapped
        if parts[0].starts_with('"') && parts[0].ends_with('"') {
            // It was just a literal with no expressions — shouldn't happen since
            // we only get here when input contains ${
            return Ok(parts[0].clone());
        }
        return Ok(parts[0].clone());
    }

    // Multiple parts — join with + for string concatenation
    // Ensure CEL expressions produce strings by wrapping in string()
    let joined: Vec<String> = parts
        .into_iter()
        .map(|p| {
            if p.starts_with('"') {
                p // Already a string literal
            } else {
                format!("string({})", p)
            }
        })
        .collect();

    Ok(joined.join(" + "))
}

/// Find the matching closing `}` for an opening `{` at `start`, respecting nesting.
fn find_matching_brace(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = start;

    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            // Track escapes with a running flag so a trailing `\\` (an
            // escaped backslash) doesn't swallow the real closing quote.
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Convert a `serde_json::Value` to a `cel::Value`.
pub fn json_to_cel(value: &Value) -> CelValue {
    match value {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                CelValue::UInt(u)
            } else if let Some(f) = n.as_f64() {
                CelValue::Float(f)
            } else {
                CelValue::Null
            }
        }
        Value::String(s) => CelValue::String(s.clone().into()),
        Value::Array(arr) => CelValue::List(arr.iter().map(json_to_cel).collect::<Vec<_>>().into()),
        Value::Object(obj) => {
            let map: HashMap<CelKey, CelValue> = obj
                .iter()
                .map(|(k, v)| (CelKey::String(k.clone().into()), json_to_cel(v)))
                .collect();
            CelValue::Map(CelMap { map: Arc::new(map) })
        }
    }
}

/// Convert a `cel::Value` to a `serde_json::Value`.
pub fn cel_value_to_json(value: &CelValue) -> Value {
    match value {
        CelValue::Null => Value::Null,
        CelValue::Bool(b) => Value::Bool(*b),
        CelValue::Int(n) => serde_json::json!(*n),
        CelValue::UInt(n) => serde_json::json!(*n),
        CelValue::Float(f) => serde_json::json!(*f),
        CelValue::String(s) => Value::String(s.to_string()),
        CelValue::List(l) => Value::Array(l.iter().map(cel_value_to_json).collect()),
        CelValue::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in m.map.iter() {
                let key_str = match k {
                    CelKey::String(s) => s.to_string(),
                    CelKey::Int(n) => n.to_string(),
                    CelKey::Uint(n) => n.to_string(),
                    CelKey::Bool(b) => b.to_string(),
                };
                obj.insert(key_str, cel_value_to_json(v));
            }
            Value::Object(obj)
        }
        _ => Value::Null,
    }
}

/// Convert a CEL value to a string representation.
///
/// Used to render the final result of an interpolated config field.
/// Floats are formatted with two decimal places (config values that
/// land on a float are typically currency / rate strings); callers
/// needing full precision should keep the value numeric rather than
/// interpolating it into a string.
fn cel_value_to_string(value: &CelValue) -> Result<String> {
    match value {
        CelValue::String(s) => Ok(s.to_string()),
        CelValue::Int(n) => Ok(n.to_string()),
        CelValue::UInt(n) => Ok(n.to_string()),
        CelValue::Float(f) => Ok(format!("{:.2}", f)),
        CelValue::Bool(b) => Ok(b.to_string()),
        CelValue::Null => Ok(String::new()),
        other => Err(anyhow::anyhow!(
            "expression must evaluate to a string, number, or boolean, got {:?}",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Header value validation
// ---------------------------------------------------------------------------

/// Validate that a header name contains only valid RFC 7230 token characters.
pub fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow::anyhow!("header name must not be empty"));
    }
    if !name.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    }) {
        return Err(anyhow::anyhow!(
            "header name '{}' contains invalid characters",
            name
        ));
    }
    Ok(())
}

/// Validate that a resolved header value does not contain header injection characters.
pub fn validate_header_value(name: &str, value: &str) -> Result<()> {
    validate_header_name(name)?;
    if value.contains('\r') || value.contains('\n') {
        return Err(anyhow::anyhow!(
            "header '{}' value contains CR/LF characters (header injection risk)",
            name
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- interpolation_to_cel ---

    #[test]
    fn literal_string_no_interpolation() {
        let dv = DynamicValue::parse("hello world").unwrap();
        let ctx = ExprContext::default();
        assert_eq!(dv.resolve(&ctx).unwrap(), "hello world");
    }

    #[test]
    fn single_expression_block() {
        let dv = DynamicValue::parse("${arguments.count > 10 ? \"high\" : \"low\"}").unwrap();

        let ctx = ExprContext {
            arguments: serde_json::json!({"count": 20}),
            ..Default::default()
        };
        let result = dv.resolve(&ctx).unwrap();
        assert_eq!(result, "high");
    }

    #[test]
    fn mixed_literal_and_expression() {
        let dv = DynamicValue::parse("https://api.example.com/${arguments.path}").unwrap();

        let ctx = ExprContext {
            arguments: serde_json::json!({"path": "v2/data"}),
            ..Default::default()
        };
        let result = dv.resolve(&ctx).unwrap();
        assert_eq!(result, "https://api.example.com/v2/data");
    }

    #[test]
    fn env_resolution_at_startup() {
        // SAFETY: test-only, single-threaded env manipulation
        unsafe { std::env::set_var("MCPGTEST_HOST", "prod.example.com") };
        let result = resolve_env_in_string("https://${env.MCPGTEST_HOST}/api").unwrap();
        assert_eq!(result, "https://prod.example.com/api");
        unsafe { std::env::remove_var("MCPGTEST_HOST") };
    }

    #[test]
    fn env_resolution_missing_var_fails() {
        let result = resolve_env_in_string("${env.MCPG_DOES_NOT_EXIST_XYZ}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not set"));
    }

    #[test]
    fn env_resolution_leaves_non_env_untouched() {
        let result = resolve_env_in_string("${arguments.x}").unwrap();
        assert_eq!(result, "${arguments.x}");
    }

    #[test]
    fn legacy_dollar_env_form_is_not_resolved() {
        // SAFETY: test-only, single-threaded env manipulation
        unsafe { std::env::set_var("MCPG_EXPR_LEGACY", "secret") };
        // Build the legacy `$`-prefixed form dynamically so it survives a
        // repo-wide `${$env. -> ${env.` sweep.
        let legacy = format!("${{{}env.MCPG_EXPR_LEGACY}}", '$');
        let result = resolve_env_in_string(&legacy).unwrap();
        assert_eq!(result, legacy);
        unsafe { std::env::remove_var("MCPG_EXPR_LEGACY") };
    }

    #[test]
    fn env_resolution_preserves_non_ascii() {
        // SAFETY: test-only, single-threaded env manipulation
        unsafe { std::env::set_var("MCPG_EXPR_NONASCII", "x") };
        let result = resolve_env_in_string("café ${env.MCPG_EXPR_NONASCII} Zürich").unwrap();
        assert_eq!(result, "café x Zürich");
        unsafe { std::env::remove_var("MCPG_EXPR_NONASCII") };
    }

    #[test]
    fn env_resolution_matches_nested_brace() {
        // SAFETY: test-only, single-threaded env manipulation
        unsafe { std::env::set_var("MCPG_EXPR_NEST_${X}", "v") };
        // The whole nested-brace name must be matched (not truncated at the
        // first `}`); the literal name is unset so it errors rather than
        // silently resolving a wrong name.
        let result = resolve_env_in_string("${env.NEST${X}}");
        assert!(result.is_err());
        unsafe { std::env::remove_var("MCPG_EXPR_NEST_${X}") };
    }

    #[test]
    fn parse_preserves_non_ascii_string_literal() {
        let dv =
            DynamicValue::<String>::parse("${arguments.country == \"Zürich\" ? \"a\" : \"b\"}");
        assert!(
            dv.is_ok(),
            "non-ASCII CEL string constant should compile intact"
        );
    }

    #[test]
    fn matching_brace_handles_escaped_backslash() {
        // A CEL string ending in an escaped backslash must not swallow the
        // real closing quote.
        let dv = DynamicValue::<String>::parse("prefix-${\"a\\\\\" + arguments.x}-suffix");
        assert!(
            dv.is_ok(),
            "trailing escaped backslash should not break brace matching"
        );
    }

    #[test]
    fn unclosed_expression_fails() {
        let result = DynamicValue::parse("${arguments.x");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unclosed"));
    }

    #[test]
    fn empty_expression_fails() {
        let result = DynamicValue::parse("${}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn dollar_prefixed_variable_ref_is_rejected() {
        // The `$`-prefix is no longer a valid variable reference; it fails to
        // compile as CEL rather than being silently stripped.
        let prefixed = format!("{}{}", '$', "{$arguments.count}");
        assert!(DynamicValue::<String>::parse(&prefixed).is_err());
    }

    // --- ExprContext integration ---

    #[test]
    fn expr_context_provides_all_variables() {
        let ctx = ExprContext {
            arguments: serde_json::json!({"x": 42}),
            tool_name: "test_tool".to_owned(),
            context: ExprRequestContext {
                principal_id: Some("user-1".to_owned()),
                trust_level: "verified".to_owned(),
                auth_provider: Some("google".to_owned()),
                session_id: Some("sess-1".to_owned()),
                transport: "http".to_owned(),
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            steps: None,
            env: Arc::new(HashMap::new()),
        };

        // Test tool_name
        let dv = DynamicValue::parse("${tool_name}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "test_tool");

        // Test arguments
        let dv = DynamicValue::parse("${arguments.x}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "42");

        // Test context fields
        let dv = DynamicValue::parse("${context.principal_id}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "user-1");

        let dv = DynamicValue::parse("${context.trust_level}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "verified");
    }

    #[test]
    fn args_alias_works_for_backward_compat() {
        let ctx = ExprContext {
            arguments: serde_json::json!({"name": "alice"}),
            ..Default::default()
        };
        // Pipeline-style: args.name
        let dv = DynamicValue::parse("${args.name}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "alice");
    }

    #[test]
    fn steps_available_in_pipeline_context() {
        let ctx = ExprContext {
            arguments: serde_json::json!({}),
            steps: Some(serde_json::json!({
                "step1": {"output": {"result": "ok"}, "is_error": false}
            })),
            ..Default::default()
        };

        let dv = DynamicValue::parse("${steps.step1.output.result}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "ok");
    }

    #[test]
    fn ternary_expression_works() {
        let ctx = ExprContext {
            arguments: serde_json::json!({"count": 5}),
            ..Default::default()
        };

        let dv = DynamicValue::parse("${arguments.count > 3 ? \"many\" : \"few\"}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "many");
    }

    #[test]
    fn numeric_expression_to_string() {
        let ctx = ExprContext {
            arguments: serde_json::json!({"count": 10}),
            ..Default::default()
        };

        let dv = DynamicValue::parse("${arguments.count}").unwrap();
        let resolved = dv.resolve(&ctx).unwrap();
        assert_eq!(resolved, "10");
    }

    // --- json_to_cel / cel_value_to_json round-trip ---

    #[test]
    fn json_cel_roundtrip_primitives() {
        let cases = vec![
            serde_json::json!(null),
            serde_json::json!(true),
            serde_json::json!(42),
            serde_json::json!("hello"),
        ];
        for input in cases {
            let cel = json_to_cel(&input);
            let back = cel_value_to_json(&cel);
            assert_eq!(input, back, "roundtrip failed for {:?}", input);
        }
    }

    #[test]
    fn json_cel_roundtrip_nested() {
        let input = serde_json::json!({
            "nested": {"count": 5},
            "items": [1, 2, 3]
        });
        let cel = json_to_cel(&input);
        let back = cel_value_to_json(&cel);
        assert_eq!(input, back);
    }

    // --- header injection validation ---

    #[test]
    fn clean_header_value_passes() {
        validate_header_value("Authorization", "Bearer token123").unwrap();
    }

    #[test]
    fn crlf_in_header_rejected() {
        let result = validate_header_value("X-Custom", "value\r\nX-Injected: evil");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("header injection"));
    }

    #[test]
    fn newline_in_header_rejected() {
        let result = validate_header_value("X-Custom", "value\nevil");
        assert!(result.is_err());
    }

    // --- interpolation_to_cel edge cases ---

    #[test]
    fn multiple_expressions_concatenated() {
        let cel = interpolation_to_cel("${arguments.a}-${arguments.b}").unwrap();
        // Should produce: string(arguments.a) + "-" + string(arguments.b)
        assert!(cel.contains("arguments.a"));
        assert!(cel.contains("arguments.b"));
        assert!(cel.contains("\"-\""));

        // Verify it evaluates correctly
        let dv = DynamicValue::parse("${arguments.a}-${arguments.b}").unwrap();
        let ctx = ExprContext {
            arguments: serde_json::json!({"a": "hello", "b": "world"}),
            ..Default::default()
        };
        assert_eq!(dv.resolve(&ctx).unwrap(), "hello-world");
    }

    #[test]
    fn env_in_expr_context() {
        let ctx = ExprContext {
            env: Arc::new(HashMap::from([(
                "API_KEY".to_owned(),
                "secret123".to_owned(),
            )])),
            ..Default::default()
        };

        let dv = DynamicValue::parse("${env.API_KEY}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "secret123");
    }

    #[test]
    fn boolean_expression_to_string() {
        let ctx = ExprContext {
            arguments: serde_json::json!({"enabled": true}),
            ..Default::default()
        };
        let dv = DynamicValue::parse("${arguments.enabled}").unwrap();
        assert_eq!(dv.resolve(&ctx).unwrap(), "true");
    }

    // --- unified grammar: ${cred://…} + bare ${env.X}/${arguments.X} ---

    #[test]
    fn cred_ref_parses_as_composite_and_resolves_via_callback() {
        let dv = DynamicValue::parse("Bearer ${cred://google/apikey}").unwrap();
        assert!(matches!(dv, DynamicValue::Composite { .. }));
        assert_eq!(dv.cred_refs(), vec!["cred://google/apikey"]);

        let ctx = ExprContext::default();
        // resolve() refuses — no credential resolver supplied.
        assert!(dv.resolve(&ctx).is_err());
        // resolve_with_credentials fills the credential.
        let out = dv
            .resolve_with_credentials(&ctx, |uri| {
                (uri == "cred://google/apikey").then(|| "SECRET_KEY".to_owned())
            })
            .unwrap();
        assert_eq!(out, "Bearer SECRET_KEY");
    }

    #[test]
    fn composite_mixes_literal_cred_and_cel() {
        let dv = DynamicValue::parse("Bearer ${cred://oauth/api} u=${arguments.user}").unwrap();
        assert!(matches!(dv, DynamicValue::Composite { .. }));
        assert_eq!(dv.cred_refs(), vec!["cred://oauth/api"]);
        let ctx = ExprContext {
            arguments: serde_json::json!({ "user": "alice" }),
            ..Default::default()
        };
        let out = dv
            .resolve_with_credentials(&ctx, |uri| {
                (uri == "cred://oauth/api").then(|| "tok123".to_owned())
            })
            .unwrap();
        assert_eq!(out, "Bearer tok123 u=alice");
    }

    #[test]
    fn bare_variable_ref_resolves_dollar_prefix_rejected() {
        let ctx = ExprContext {
            arguments: serde_json::json!({ "path": "v2" }),
            ..Default::default()
        };
        // Standard bare form resolves.
        assert_eq!(
            DynamicValue::parse("/${arguments.path}")
                .unwrap()
                .resolve(&ctx)
                .unwrap(),
            "/v2"
        );
        // The `$`-prefixed form is rejected (invalid CEL). Built dynamically
        // so a `${$ -> ${` sweep can't rewrite the literal.
        let prefixed = format!("/{}{}", '$', "{$arguments.path}");
        assert!(DynamicValue::<String>::parse(&prefixed).is_err());
    }

    #[test]
    fn env_bare_form_resolves_dollar_prefix_does_not() {
        // SAFETY: test-only env manipulation; unique name.
        unsafe { std::env::set_var("MCPG_EXPR_ENV_STD", "host.example") };
        assert_eq!(
            resolve_env_in_string("https://${env.MCPG_EXPR_ENV_STD}/x").unwrap(),
            "https://host.example/x"
        );
        // The `$`-prefixed form passes through literally (not resolved).
        let legacy = format!("https://{}{}/x", '$', "{$env.MCPG_EXPR_ENV_STD}");
        assert_eq!(resolve_env_in_string(&legacy).unwrap(), legacy);
        unsafe { std::env::remove_var("MCPG_EXPR_ENV_STD") };
    }

    /// SECURITY: a `cred://` value arriving through a request ARGUMENT
    /// that an operator template interpolates is NOT a credential
    /// reference. Credential refs are parsed only from the operator
    /// template's own `${cred://…}` tokens, so `cred_refs()` is empty, the
    /// credential resolver is never consulted for request data, and the
    /// value passes through verbatim — config-origin by construction.
    #[test]
    fn request_arg_value_can_never_introduce_a_cred_ref() {
        let dv = DynamicValue::parse("${arguments.x}").unwrap();
        assert!(matches!(dv, DynamicValue::Expression { .. }));
        assert!(dv.cred_refs().is_empty());

        for smuggled in ["cred://static/secret", "${cred://static/secret}"] {
            let ctx = ExprContext {
                arguments: serde_json::json!({ "x": smuggled }),
                ..Default::default()
            };
            // The resolver WOULD leak a secret if it were ever consulted.
            let out = dv
                .resolve_with_credentials(&ctx, |_uri| Some("LEAKED_SECRET".to_owned()))
                .unwrap();
            assert_eq!(
                out, smuggled,
                "request-arg value must pass through verbatim"
            );
            assert!(
                !out.contains("LEAKED_SECRET"),
                "credential resolver must never run on request-argument data"
            );
        }
    }
}
