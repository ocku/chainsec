use std::{cell::Cell, collections::HashSet, fmt, path::Path, rc::Rc};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

use crate::{
    error::{Error, Result},
    model::Dependency,
};

/// Collects unique manifest dependencies while enforcing the package budget at insertion time.
///
/// Parsers use this directly while expanding declaration sections, groups, and workspaces so they
/// never need to build an over-limit intermediate dependency vector.
pub(in crate::manifests) struct BoundedDependencyCollector {
    dependencies: Vec<Dependency>,
    known: HashSet<Dependency>,
    max_packages: usize,
}

impl BoundedDependencyCollector {
    pub(in crate::manifests) fn new(max_packages: usize) -> Self {
        Self {
            dependencies: Vec::new(),
            known: HashSet::new(),
            max_packages,
        }
    }

    pub(in crate::manifests) fn from_dependencies(
        dependencies: Vec<Dependency>,
        max_packages: usize,
    ) -> Result<Self> {
        let mut collector = Self::new(max_packages);
        collector.extend(dependencies)?;
        Ok(collector)
    }

    pub(in crate::manifests) fn push(&mut self, dependency: Dependency) -> Result<()> {
        if self.known.contains(&dependency) {
            return Ok(());
        }
        if self.dependencies.len() >= self.max_packages {
            return Err(Error::LimitExceeded {
                resource: "manifest dependencies".to_owned(),
                limit: u64::try_from(self.max_packages).unwrap_or(u64::MAX),
            });
        }
        self.known.insert(dependency.clone());
        self.dependencies.push(dependency);
        Ok(())
    }

    pub(in crate::manifests) fn extend(
        &mut self,
        incoming: impl IntoIterator<Item = Dependency>,
    ) -> Result<()> {
        for dependency in incoming {
            self.push(dependency)?;
        }
        Ok(())
    }

    pub(in crate::manifests) fn into_dependencies(self) -> Vec<Dependency> {
        self.dependencies
    }
}

pub(in crate::manifests) fn extend_dependencies_bounded(
    dependencies: &mut Vec<Dependency>,
    incoming: impl IntoIterator<Item = Dependency>,
    max_packages: usize,
) -> Result<()> {
    let existing = std::mem::take(dependencies);
    let mut collector = BoundedDependencyCollector::from_dependencies(existing, max_packages)?;
    let result = collector.extend(incoming);
    *dependencies = collector.into_dependencies();
    result
}

/// Parses a YAML manifest without allowing aliases to expand into an object graph larger than the
/// bounded input itself. The budget is derived from the actual file bytes, so Yarn and pnpm share
/// the configured manifest limit rather than gaining a separate parser-specific limit.
pub(in crate::manifests) fn parse_bounded_yaml_json(path: &Path, text: &str) -> Result<JsonValue> {
    let budget = Rc::new(YamlNodeBudget {
        remaining: Cell::new(text.len().saturating_add(1)),
    });
    BoundedJsonSeed { budget }
        .deserialize(serde_yaml::Deserializer::from_str(text))
        .map_err(|error| super::manifest_error(path, error))
}

struct YamlNodeBudget {
    remaining: Cell<usize>,
}

impl YamlNodeBudget {
    fn charge<E: de::Error>(&self) -> std::result::Result<(), E> {
        let remaining = self.remaining.get();
        if remaining == 0 {
            return Err(E::custom(
                "expanded YAML node count exceeds the bounded manifest input size",
            ));
        }
        self.remaining.set(remaining - 1);
        Ok(())
    }
}

#[derive(Clone)]
struct BoundedJsonSeed {
    budget: Rc<YamlNodeBudget>,
}

impl<'de> DeserializeSeed<'de> for BoundedJsonSeed {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.budget.charge()?;
        deserializer.deserialize_any(BoundedJsonVisitor {
            budget: self.budget,
        })
    }
}

struct BoundedJsonVisitor {
    budget: Rc<YamlNodeBudget>,
}

impl BoundedJsonVisitor {
    fn seed(&self) -> BoundedJsonSeed {
        BoundedJsonSeed {
            budget: Rc::clone(&self.budget),
        }
    }
}

impl<'de> Visitor<'de> for BoundedJsonVisitor {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML value representable as JSON")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
        JsonNumber::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite YAML number cannot be represented as JSON"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.seed().deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(self.seed())? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut mapping: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = JsonMap::with_capacity(mapping.size_hint().unwrap_or(0));
        while let Some(key) = mapping.next_key_seed(self.seed())? {
            let JsonValue::String(key) = key else {
                return Err(de::Error::custom("YAML mapping keys must be strings"));
            };
            values.insert(key, mapping.next_value_seed(self.seed())?);
        }
        Ok(JsonValue::Object(values))
    }
}

pub(in crate::manifests) fn optional_json_string<'a>(
    path: &Path,
    object: &'a JsonMap<String, JsonValue>,
    field: &str,
    context: &str,
) -> Result<Option<&'a str>> {
    object
        .get(field)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                super::manifest_error(path, format!("{context} {field} must be a string"))
            })
        })
        .transpose()
}

pub(in crate::manifests) fn optional_toml_string<'a>(
    path: &Path,
    table: &'a ::toml::value::Table,
    field: &str,
    context: &str,
) -> Result<Option<&'a str>> {
    table
        .get(field)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                super::manifest_error(path, format!("{context} {field} must be a string"))
            })
        })
        .transpose()
}
