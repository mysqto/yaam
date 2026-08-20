//! Declared attributes and their classification.
//!
//! `structural` attributes may sit in plaintext frontmatter and are queryable and retained.
//! `sensitive` attributes belong in the record body, which is sealed for erasable records. An
//! undeclared key is rejected — that is what keeps unerasable data out of copies which key
//! destruction cannot reach.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Error, spec_yaml};

/// Attribute type names a declaration may use.
///
/// Checked at load but not retained: the frozen surface reports classification only, and [`Value`]
/// already carries its own type. Rejecting an unrecognised name still catches a typo in the spec at
/// load time instead of letting it silently declare nothing.
const DECLARED_TYPES: [&str; 3] = ["string", "integer", "boolean"];

/// Whether an attribute may live in plaintext frontmatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Queryable, retained, plaintext.
    Structural,
    /// Must live in the sealed body.
    Sensitive,
}

impl Class {
    /// Reads the class name as `spec/attrs-schema.yaml` spells it.
    fn from_name(name: &str, owner: &str) -> crate::Result<Self> {
        match name {
            "structural" => Ok(Self::Structural),
            "sensitive" => Ok(Self::Sensitive),
            other => Err(Error::Invalid(format!(
                "attribute `{owner}` has unknown class `{other}`"
            ))),
        }
    }
}

/// A scalar attribute value. Deliberately flat — `attrs` is not a document store.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    /// Text.
    Text(String),
    /// Whole number.
    Int(i64),
    /// Truth value.
    Bool(bool),
}

/// The declared attribute surface, keyed by action.
#[derive(Debug, Clone, Default)]
pub struct Schema {
    actions: BTreeMap<String, BTreeMap<String, Class>>,
}

impl Schema {
    /// Loads from `attrs-schema.yaml` content.
    ///
    /// # Examples
    /// ```
    /// use std::collections::BTreeMap;
    /// use yaam_contract::attrs::{Class, Schema, Value};
    ///
    /// let schema = Schema::from_yaml(concat!(
    ///     "actions:\n",
    ///     "  deploy:\n",
    ///     "    attrs:\n",
    ///     "      service: { type: string, class: structural }\n",
    /// ))?;
    /// assert_eq!(schema.class_of("deploy", "service")?, Class::Structural);
    ///
    /// let attrs = BTreeMap::from([("service".to_owned(), Value::Text("api".to_owned()))]);
    /// schema.validate_frontmatter("deploy", &attrs)?;
    /// # Ok::<(), yaam_contract::Error>(())
    /// ```
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        let doc = spec_yaml::single_document(yaml)?;
        spec_yaml::check_version(&doc)?;

        let mut actions = BTreeMap::new();
        for (key, value) in spec_yaml::required_mapping(&doc, "actions")? {
            let action = spec_yaml::key_name(key, "action")?;
            let mut declared = BTreeMap::new();
            if let Some(node) = value.as_mapping_get("attrs") {
                let attrs = node.as_mapping().ok_or_else(|| {
                    Error::Invalid(format!("action `{action}` has a non-mapping `attrs`"))
                })?;
                for (attr_key, attr_value) in attrs {
                    let name = spec_yaml::key_name(attr_key, "attribute")?;
                    let owner = format!("{action}.{name}");
                    let declared_type = spec_yaml::required_str(attr_value, "type", &owner)?;
                    if !DECLARED_TYPES.contains(&declared_type) {
                        return Err(Error::Invalid(format!(
                            "attribute `{owner}` has unknown type `{declared_type}`"
                        )));
                    }
                    let class = spec_yaml::required_str(attr_value, "class", &owner)?;
                    declared.insert(name.to_owned(), Class::from_name(class, &owner)?);
                }
            }
            actions.insert(action.to_owned(), declared);
        }
        Ok(Self { actions })
    }

    /// Rejects undeclared keys, and `sensitive` keys presented as frontmatter.
    ///
    /// An action absent from the schema declares nothing, so every attribute presented for it is
    /// undeclared. Vetting the action name itself belongs to whoever owns the action vocabulary,
    /// not to the attribute surface.
    pub fn validate_frontmatter(
        &self,
        action: &str,
        attrs: &BTreeMap<String, Value>,
    ) -> crate::Result<()> {
        let declared = self.actions.get(action);
        for key in attrs.keys() {
            match declared.and_then(|d| d.get(key)) {
                Some(Class::Structural) => {}
                Some(Class::Sensitive) => {
                    return Err(Error::SensitiveAttrInFrontmatter(key.clone()));
                }
                None => {
                    return Err(Error::UndeclaredAttr {
                        action: action.to_owned(),
                        key: key.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Classification of one declared key.
    ///
    /// An undeclared key and an unknown action are the same failure: nothing can be declared for an
    /// action the schema does not carry.
    pub fn class_of(&self, action: &str, key: &str) -> crate::Result<Class> {
        self.actions
            .get(action)
            .and_then(|declared| declared.get(key))
            .copied()
            .ok_or_else(|| Error::UndeclaredAttr {
                action: action.to_owned(),
                key: key.to_owned(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema the workspace ships, so a spec edit that breaks a rule fails here.
    const SHIPPED: &str = include_str!("../../../spec/attrs-schema.yaml");

    fn shipped() -> Schema {
        Schema::from_yaml(SHIPPED).expect("the shipped spec must load")
    }

    fn attrs(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn shipped_spec_classifies_declared_keys() {
        let s = shipped();
        assert_eq!(s.class_of("deploy", "service").unwrap(), Class::Structural);
        assert_eq!(
            s.class_of("transact", "amount_minor").unwrap(),
            Class::Sensitive
        );
        assert_eq!(s.class_of("reply", "chunks").unwrap(), Class::Structural);
    }

    #[test]
    fn structural_frontmatter_is_accepted() {
        let ok = attrs(&[
            ("service", Value::Text("api".to_owned())),
            ("duration_ms", Value::Int(12)),
        ]);
        shipped().validate_frontmatter("deploy", &ok).unwrap();
    }

    #[test]
    fn empty_frontmatter_is_accepted() {
        shipped()
            .validate_frontmatter("deploy", &BTreeMap::new())
            .unwrap();
    }

    #[test]
    fn undeclared_key_is_rejected() {
        let err = shipped()
            .validate_frontmatter("deploy", &attrs(&[("who", Value::Bool(true))]))
            .expect_err("`who` is not declared for deploy");
        assert!(
            matches!(err, Error::UndeclaredAttr { ref action, ref key } if action == "deploy" && key == "who")
        );
    }

    #[test]
    fn a_key_declared_for_another_action_is_still_undeclared() {
        assert!(
            shipped()
                .validate_frontmatter(
                    "deploy",
                    &attrs(&[("provider", Value::Text("p".to_owned()))])
                )
                .is_err()
        );
    }

    #[test]
    fn sensitive_key_is_rejected_from_frontmatter() {
        for key in ["decline_reason", "amount_minor"] {
            let err = shipped()
                .validate_frontmatter("transact", &attrs(&[(key, Value::Int(1))]))
                .expect_err("sensitive keys belong in the body");
            assert!(matches!(err, Error::SensitiveAttrInFrontmatter(ref k) if k == key));
        }
    }

    #[test]
    fn an_unknown_action_declares_nothing() {
        let s = shipped();
        // Nothing presented, nothing to reject.
        s.validate_frontmatter("no_such_action", &BTreeMap::new())
            .unwrap();
        assert!(
            s.validate_frontmatter("no_such_action", &attrs(&[("service", Value::Int(1))]))
                .is_err()
        );
        assert!(matches!(
            s.class_of("no_such_action", "service"),
            Err(Error::UndeclaredAttr { .. })
        ));
    }

    #[test]
    fn class_of_rejects_an_undeclared_key() {
        assert!(shipped().class_of("deploy", "who").is_err());
    }

    #[test]
    fn default_schema_declares_nothing() {
        assert!(Schema::default().class_of("deploy", "service").is_err());
    }

    #[test]
    fn an_action_may_declare_no_attrs() {
        let s = Schema::from_yaml("actions:\n  ping:\n    outcome: [success]\n").unwrap();
        s.validate_frontmatter("ping", &BTreeMap::new()).unwrap();
        assert!(s.class_of("ping", "anything").is_err());
    }

    #[test]
    fn from_yaml_rejects_malformed_specs() {
        for (label, yaml) in [
            ("not yaml", "actions: [\n"),
            ("no actions", "version: 1\n"),
            ("actions not a mapping", "actions: []\n"),
            ("non-string action name", "actions:\n  1:\n    attrs: {}\n"),
            ("attrs not a mapping", "actions:\n  a:\n    attrs: []\n"),
            (
                "non-string attr name",
                "actions:\n  a:\n    attrs:\n      1: { type: string, class: structural }\n",
            ),
            (
                "missing type",
                "actions:\n  a:\n    attrs:\n      k: { class: structural }\n",
            ),
            (
                "unknown type",
                "actions:\n  a:\n    attrs:\n      k: { type: blob, class: structural }\n",
            ),
            (
                "missing class",
                "actions:\n  a:\n    attrs:\n      k: { type: string }\n",
            ),
            (
                "unknown class",
                "actions:\n  a:\n    attrs:\n      k: { type: string, class: secret }\n",
            ),
            ("future version", "version: 99\nactions: {}\n"),
        ] {
            assert!(Schema::from_yaml(yaml).is_err(), "{label} must be rejected");
        }
    }

    #[test]
    fn every_declared_type_loads() {
        for declared in DECLARED_TYPES {
            let yaml = format!(
                "actions:\n  a:\n    attrs:\n      k: {{ type: {declared}, class: sensitive }}\n"
            );
            assert_eq!(
                Schema::from_yaml(&yaml)
                    .unwrap()
                    .class_of("a", "k")
                    .unwrap(),
                Class::Sensitive
            );
        }
    }

    #[test]
    fn values_and_classes_survive_json() {
        let values = vec![
            Value::Text("x".to_owned()),
            Value::Int(-1),
            Value::Bool(false),
        ];
        let json = serde_json::to_string(&values).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<Value>>(&json).unwrap(),
            values,
            "untagged values must not blur into one another"
        );
        assert_eq!(
            serde_json::from_str::<Class>(r#""sensitive""#).unwrap(),
            Class::Sensitive
        );
        assert_eq!(
            serde_json::to_string(&Class::Structural).unwrap(),
            r#""structural""#
        );
    }
}
