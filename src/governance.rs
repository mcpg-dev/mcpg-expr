//! The `governance` block a gateway binding, a federation or a registry's
//! `defaults` carries: a trust floor, a CEL `allow_if` condition and the
//! OAuth scopes a caller must hold.
//!
//! The gateway reads its config with these types, and anything that writes
//! a block into a gateway's config on someone else's behalf (the Kubernetes
//! operator) checks it with the same types first, so a block one accepts is
//! a block the other boots with.

use anyhow::{Context as AnyhowContext, Result};
use serde::{Deserialize, Serialize};

/// A caller trust level, lowest first.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevelConfig {
    Unauthenticated,
    #[default]
    HeaderAsserted,
    Verified,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
// A misspelled key (`alow_if`, or the central rules' `cel_allow_if`) would
// otherwise parse to "no condition" and silently drop the control.
#[serde(deny_unknown_fields)]
pub struct BackendGovernanceConfig {
    /// The lowest caller trust level the capability accepts. When unset, a
    /// binding takes `governance.policy.tool_access.default_minimum_trust`,
    /// and a federation, a registry's `defaults` or an openapi source's
    /// auto-exposed capabilities take `header_asserted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_trust: Option<TrustLevelConfig>,
    #[serde(default)]
    pub allow_if: Option<String>,
    /// Scopes the caller's credential MUST carry to invoke this binding
    /// (OAuth `scope`, or an AAuth auth token's `scope`). A caller short of
    /// them is answered with the step-up challenge naming the missing scopes
    /// (`WWW-Authenticate … error="insufficient_scope"`; for an AAuth person
    /// or auth-token caller, `AAuth-Requirement: requirement=auth-token`
    /// carrying a resource token). Empty (the default) means no scope
    /// requirement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
}

impl BackendGovernanceConfig {
    /// Check the block the way the gateway does at config load. `path` is
    /// the config path of the object that holds the block; errors name
    /// `<path>.governance.<key>`.
    pub fn validate(&self, path: &str) -> Result<()> {
        if self
            .allow_if
            .as_ref()
            .is_some_and(|expr| expr.trim().is_empty())
        {
            return Err(anyhow::anyhow!(
                "{}.governance.allow_if must not be empty when provided",
                path
            ));
        }
        if let Some(expr) = &self.allow_if {
            validate_allow_if(expr, &format!("{path}.governance.allow_if"))?;
        }
        if self
            .required_scopes
            .iter()
            .any(|s| s.trim().is_empty() || s.contains(char::is_whitespace))
        {
            return Err(anyhow::anyhow!(
                "{}.governance.required_scopes entries must be non-empty scope values without \
                 whitespace",
                path
            ));
        }
        Ok(())
    }

    /// Parse a raw `governance` block and check it; `path` as for
    /// [`Self::validate`].
    pub fn from_value(value: &serde_json::Value, path: &str) -> Result<Self> {
        let governance: Self =
            serde_json::from_value(value.clone()).with_context(|| format!("{path}.governance"))?;
        governance.validate(path)?;
        Ok(governance)
    }
}

/// Compile a governance `allow_if` with the CEL compiler the gateway's
/// policy gate uses, so validation refuses exactly the expressions the gate
/// could not enforce. `config_path` names the key in the error.
pub fn validate_allow_if(source: &str, config_path: &str) -> Result<()> {
    cel::Program::compile(source)
        .map(drop)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("failed to compile {config_path}: {source}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(value: serde_json::Value) -> Result<BackendGovernanceConfig> {
        BackendGovernanceConfig::from_value(&value, "spec.federate")
    }

    #[test]
    fn a_valid_block_parses() {
        let governance = check(serde_json::json!({
            "minimum_trust": "verified",
            "allow_if": "\"ops\" in identity.groups",
            "required_scopes": ["crm.read"],
        }))
        .expect("valid block");
        assert_eq!(governance.minimum_trust, Some(TrustLevelConfig::Verified));
        assert_eq!(
            check(serde_json::json!({})).expect("empty block"),
            Default::default()
        );
    }

    #[test]
    fn an_invalid_block_names_the_key() {
        for (value, key) in [
            (
                serde_json::json!({ "cel_allow_if": "true" }),
                "spec.federate.governance",
            ),
            (
                serde_json::json!({ "minimum_trust": "admin" }),
                "spec.federate.governance",
            ),
            (
                serde_json::json!({ "allow_if": "tool_name == " }),
                "spec.federate.governance.allow_if",
            ),
            (
                serde_json::json!({ "allow_if": "  " }),
                "spec.federate.governance.allow_if",
            ),
            (
                serde_json::json!({ "required_scopes": ["crm read"] }),
                "spec.federate.governance.required_scopes",
            ),
        ] {
            let error = check(value.clone()).expect_err("invalid block");
            assert!(format!("{error:#}").contains(key), "{value}: {error:#}");
        }
    }
}
