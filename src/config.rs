use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result};
use directories::BaseDirs;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub login: LoginProfile,
    #[serde(default)]
    pub aws: AwsSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginProfile {
    pub name: String,
    pub login_url: String,
    pub username: String,
    pub password: String,
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub selectors: Selectors,
    #[serde(default)]
    pub waits: Waits,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AwsSection {
    #[serde(default)]
    pub accounts: Vec<AwsAccount>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AwsAccount {
    pub label: String,
    #[serde(rename = "iam-role")]
    pub iam_role: String,
    #[serde(rename = "saml-provider")]
    pub saml_provider: String,
    pub account: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Selectors {
    pub username: Option<String>,
    pub password: Option<String>,
    pub submit: Option<String>,
    pub otp: Option<String>,
    pub otp_submit: Option<String>,
    pub saml_response: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Waits {
    #[serde(default = "default_otp_timeout_secs")]
    pub otp_timeout_secs: u64,
    #[serde(default = "default_saml_timeout_secs")]
    pub saml_timeout_secs: u64,
}

impl Default for Waits {
    fn default() -> Self {
        Self {
            otp_timeout_secs: default_otp_timeout_secs(),
            saml_timeout_secs: default_saml_timeout_secs(),
        }
    }
}

fn default_otp_timeout_secs() -> u64 {
    120
}

fn default_saml_timeout_secs() -> u64 {
    120
}

pub fn load_config() -> Result<Config> {
    let contents = load_config_text()?;
    parse_config(&contents)
}

pub fn config_path() -> PathBuf {
    if let Ok(path) = env::var("RS_AWS_SAML_CONFIG") {
        return PathBuf::from(path);
    }

    if let Some(base_dirs) = BaseDirs::new() {
        return base_dirs.home_dir().join(".rs-aws-saml.toml");
    }

    PathBuf::from("profiles.toml")
}

pub fn load_config_text() -> Result<String> {
    let path = config_path();
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {}", path.display()))?;
    Ok(contents)
}

pub fn parse_config(contents: &str) -> Result<Config> {
    let config: Config =
        toml::from_str(contents).with_context(|| "Invalid TOML format in config")?;
    Ok(config)
}

pub fn save_config_text(contents: &str) -> Result<PathBuf> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory {}", parent.display())
            })?;
        }
    }
    fs::write(&path, contents)
        .with_context(|| format!("Failed to write config at {}", path.display()))?;
    Ok(path)
}
