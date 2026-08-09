use crate::config::Config;
use crate::paths::field_path;
use crate::process::run_checked;
use anyhow::{bail, Context, Result};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SUPPORTED_VERSIONS: &str = ">=2.2.2, <3.0.0";
pub(crate) const CREDENTIAL_ENVIRONMENT: &[&str] = &[
    "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
    "PROTON_PASS_USERNAME",
    "PROTON_PASS_USERNAME_FILE",
    "PROTON_PASS_PASSWORD",
    "PROTON_PASS_PASSWORD_FILE",
    "PROTON_PASS_EXTRA_PASSWORD",
    "PROTON_PASS_EXTRA_PASSWORD_FILE",
    "PROTON_PASS_TOTP",
    "PROTON_PASS_TOTP_FILE",
];

fn proton_environment() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PASS_LOG_LEVEL"), OsString::from("off")),
        (OsString::from("MUON_LOG_LEVEL"), OsString::from("off")),
        (
            OsString::from("PROTON_PASS_NO_UPDATE_CHECK"),
            OsString::from("1"),
        ),
        (
            OsString::from("PROTON_PASS_DISABLE_TELEMETRY"),
            OsString::from("1"),
        ),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemSummary {
    pub id: String,
    pub modify_time: String,
}

#[derive(Debug)]
pub struct Inventory {
    pub items: Vec<ItemSummary>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(String);

impl SecretValue {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub struct RemoteField {
    pub qualified_name: String,
    pub path: String,
    pub value: SecretValue,
}

pub struct RemoteItem {
    pub id: String,
    pub modify_time: String,
    pub fields: Vec<RemoteField>,
}

pub struct ProtonClient<'a> {
    config: &'a Config,
}

impl<'a> ProtonClient<'a> {
    #[must_use]
    pub const fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn version(&self) -> Result<Version> {
        let mut output = run_checked(
            &self.config.proton_cli,
            &[OsString::from("--version")],
            None,
            &proton_environment(),
            CREDENTIAL_ENVIRONMENT,
            "Proton CLI version check failed",
        )?;
        let text =
            std::str::from_utf8(&output).context("Proton CLI returned a non-UTF-8 version")?;
        let version = text
            .split_whitespace()
            .find_map(|token| Version::parse(token).ok())
            .context("Proton CLI returned an unrecognized version")?;
        output.zeroize();

        let requirement = VersionReq::parse(SUPPORTED_VERSIONS)
            .context("internal Proton CLI version requirement is invalid")?;
        if !requirement.matches(&version) {
            bail!("unsupported Proton CLI version {version}; required {SUPPORTED_VERSIONS}");
        }
        Ok(version)
    }

    pub fn verify_session(&self) -> Result<()> {
        let mut output = run_checked(
            &self.config.proton_cli,
            &[
                OsString::from("info"),
                OsString::from("--output"),
                OsString::from("json"),
            ],
            None,
            &proton_environment(),
            CREDENTIAL_ENVIRONMENT,
            "Proton session check failed",
        )?;
        #[allow(clippy::zero_sized_map_values)]
        let valid = serde_json::from_slice::<
            std::collections::HashMap<String, serde::de::IgnoredAny>,
        >(&output)
        .is_ok();
        output.zeroize();
        if !valid {
            bail!("Proton session check returned an invalid response");
        }
        Ok(())
    }

    pub fn inventory(&self) -> Result<Inventory> {
        let args = vec![
            OsString::from("item"),
            OsString::from("list"),
            OsString::from("--share-id"),
            OsString::from(&self.config.vault_share_id),
            OsString::from("--filter-type"),
            OsString::from("custom"),
            OsString::from("--filter-state"),
            OsString::from("active"),
            OsString::from("--output"),
            OsString::from("json"),
        ];
        let mut output = run_checked(
            &self.config.proton_cli,
            &args,
            None,
            &proton_environment(),
            CREDENTIAL_ENVIRONMENT,
            "Proton inventory request failed",
        )?;
        let parsed = serde_json::from_slice::<ListOutput>(&output);
        output.zeroize();
        let parsed = parsed.context("Proton inventory response has an unsupported schema")?;

        let mut ids = HashSet::new();
        let mut items = Vec::with_capacity(parsed.items.len());
        for item in parsed.items {
            if item.id.is_empty()
                || item.share_id != self.config.vault_share_id
                || !item.state.eq_ignore_ascii_case("active")
                || item.item_type != "custom"
                || item.modify_time.is_empty()
                || !ids.insert(item.id.clone())
            {
                bail!("Proton inventory failed completeness validation");
            }
            items.push(ItemSummary {
                id: item.id,
                modify_time: item.modify_time,
            });
        }
        items.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Inventory { items })
    }

    pub fn view_custom_item(&self, summary: &ItemSummary) -> Result<RemoteItem> {
        let args = vec![
            OsString::from("item"),
            OsString::from("view"),
            OsString::from("--share-id"),
            OsString::from(&self.config.vault_share_id),
            OsString::from("--item-id"),
            OsString::from(&summary.id),
            OsString::from("--output"),
            OsString::from("json"),
        ];
        let mut output = run_checked(
            &self.config.proton_cli,
            &args,
            None,
            &proton_environment(),
            CREDENTIAL_ENVIRONMENT,
            "Proton item request failed",
        )?;
        let parsed = serde_json::from_slice::<ViewOutput>(&output);
        output.zeroize();
        let parsed = parsed.context("Proton item response has an unsupported schema")?;

        let item = parsed.item;
        if item.id != summary.id
            || item.share_id != self.config.vault_share_id
            || !item.state.eq_ignore_ascii_case("active")
            || item.modify_time != summary.modify_time
        {
            bail!("Proton item changed during synchronization; retry the sync");
        }

        let ItemContent::Custom(CustomContent { sections }) = item.content.content;
        let mut fields = Vec::new();
        let mut qualified_names = HashSet::new();
        for section in sections {
            for field in section.section_fields {
                let value = match field.content {
                    FieldContent::Text(value) | FieldContent::Hidden(value) => value,
                    FieldContent::Totp(_) | FieldContent::Timestamp(_) => continue,
                };
                if value.is_empty() {
                    continue;
                }
                let path = field_path(
                    &self.config.target_prefix,
                    &item.content.title,
                    &section.section_name,
                    &field.name,
                )?;
                let qualified_name = format!("{}.{}", section.section_name, field.name);
                if !qualified_names.insert(qualified_name.clone()) {
                    bail!("custom item contains duplicate qualified field names");
                }
                fields.push(RemoteField {
                    qualified_name,
                    path,
                    value,
                });
            }
        }

        Ok(RemoteItem {
            id: item.id,
            modify_time: item.modify_time,
            fields,
        })
    }
}

#[derive(Deserialize)]
struct ListOutput {
    items: Vec<ListItem>,
}

#[derive(Deserialize)]
struct ListItem {
    id: String,
    share_id: String,
    state: String,
    modify_time: String,
    item_type: String,
}

#[derive(Deserialize)]
struct ViewOutput {
    item: ViewItem,
}

#[derive(Deserialize)]
struct ViewItem {
    id: String,
    share_id: String,
    state: String,
    modify_time: String,
    content: ItemData,
}

#[derive(Deserialize)]
struct ItemData {
    title: String,
    content: ItemContent,
}

#[derive(Deserialize)]
enum ItemContent {
    Custom(CustomContent),
}

#[derive(Deserialize)]
struct CustomContent {
    sections: Vec<CustomSection>,
}

#[derive(Deserialize)]
struct CustomSection {
    section_name: String,
    section_fields: Vec<CustomField>,
}

#[derive(Deserialize)]
struct CustomField {
    name: String,
    content: FieldContent,
}

#[derive(Deserialize)]
enum FieldContent {
    Text(SecretValue),
    Hidden(SecretValue),
    Totp(serde::de::IgnoredAny),
    Timestamp(serde::de::IgnoredAny),
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config() -> Config {
        Config {
            vault_share_id: "share-1".into(),
            password_store_dir: PathBuf::from("/tmp/store"),
            target_prefix: "coding".into(),
            proton_cli: PathBuf::from("pass-cli"),
            pass_command: PathBuf::from("pass"),
            gpg_command: PathBuf::from("gpg"),
            stale_after_secs: 86_400,
        }
    }

    #[test]
    fn parses_222_inventory_fixture() {
        let fixture = br#"{
          "items": [{
            "id":"item-1","share_id":"share-1","vault_id":"vault-1",
            "state":"Active","flags":[],"create_time":"2026-01-01T00:00:00",
            "modify_time":"2026-02-02T03:04:05","title":"Project",
            "item_type":"custom"
          }]
        }"#;
        let parsed: ListOutput = serde_json::from_slice(fixture).unwrap();
        assert_eq!(parsed.items[0].id, "item-1");
    }

    #[test]
    fn parses_225_custom_fields_and_skips_unsupported_values() {
        let fixture = br#"{
          "item": {
            "id":"item-1","share_id":"share-1","vault_id":"vault-1",
            "state":"Active","flags":[],"create_time":"2026-01-01T00:00:00",
            "modify_time":"2026-02-02T03:04:05",
            "content": {
              "title":"Project","note":"ignored","item_uuid":"uuid",
              "content":{"Custom":{"sections":[{"section_name":"Tokens","section_fields":[
                {"name":"API","content":{"Hidden":"secret"}},
                {"name":"URL","content":{"Text":"https://example.test"}},
                {"name":"TOTP","content":{"Totp":"otpauth://ignored"}},
                {"name":"When","content":{"Timestamp":123}}
              ]}]}},"extra_fields":[]
            }
          },"attachments":[]
        }"#;
        let parsed: ViewOutput = serde_json::from_slice(fixture).unwrap();
        let summary = ItemSummary {
            id: "item-1".into(),
            modify_time: "2026-02-02T03:04:05".into(),
        };
        let item = extract_for_test(&config(), parsed, &summary).unwrap();
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].path, "coding/Project/Tokens/API");
        assert_eq!(item.fields[0].value.as_bytes(), b"secret");
    }

    fn extract_for_test(
        config: &Config,
        parsed: ViewOutput,
        summary: &ItemSummary,
    ) -> Result<RemoteItem> {
        let item = parsed.item;
        if item.id != summary.id || item.modify_time != summary.modify_time {
            bail!("mismatch");
        }
        let ItemContent::Custom(custom) = item.content.content;
        let mut fields = Vec::new();
        for section in custom.sections {
            for field in section.section_fields {
                let (FieldContent::Text(value) | FieldContent::Hidden(value)) = field.content
                else {
                    continue;
                };
                fields.push(RemoteField {
                    qualified_name: format!("{}.{}", section.section_name, field.name),
                    path: field_path(
                        &config.target_prefix,
                        &item.content.title,
                        &section.section_name,
                        &field.name,
                    )?,
                    value,
                });
            }
        }
        Ok(RemoteItem {
            id: item.id,
            modify_time: item.modify_time,
            fields,
        })
    }
}
