use std::{
    collections::HashMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use aws_sdk_sts::Client;
use aws_smithy_types::date_time::Format;
use aws_smithy_types::DateTime;
use directories::BaseDirs;
use configparser::ini::Ini;

use crate::config::AwsAccount;

#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub label: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialsStatus {
    pub expiration: Option<DateTime>,
}

pub fn assume_roles_with_saml(
    saml_response: &str,
    accounts: &[AwsAccount],
    on_status: impl FnMut(&str),
) -> Result<Vec<AwsCredentials>> {
    let saml_assertion = saml_response.to_string();
    let accounts = accounts.to_vec();
    let mut on_status = on_status;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    rt.block_on(async move {
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let shared_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let sts_config =
            aws_sdk_sts::config::Builder::from(&shared_config).allow_no_auth().build();
        let client = Client::from_conf(sts_config);

        let mut results = Vec::new();
        for account in accounts {
            on_status(&format!("Assuming role for {}", account.label));
            let role_arn = format!("arn:aws:iam::{}:role/{}", account.account, account.iam_role);
            let principal_arn = format!(
                "arn:aws:iam::{}:saml-provider/{}",
                account.account, account.saml_provider
            );

            let response = client
                .assume_role_with_saml()
                .role_arn(role_arn)
                .principal_arn(principal_arn)
                .saml_assertion(&saml_assertion)
                .send()
                .await
                .with_context(|| format!("AssumeRoleWithSAML failed for {}", account.label))?;

            let credentials = response
                .credentials()
                .context("Missing credentials in STS response")?;

            results.push(AwsCredentials {
                label: account.label,
                access_key_id: credentials.access_key_id().to_string(),
                secret_access_key: credentials.secret_access_key().to_string(),
                session_token: credentials.session_token().to_string(),
                expiration: Some(credentials.expiration().to_string()),
            });
        }

        Ok(results)
    })
}

pub fn write_credentials(creds: &[AwsCredentials]) -> Result<PathBuf> {
    let path = credentials_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    let mut ini = load_credentials_ini(&path)?;

    for cred in creds {
        ini.set(
            &cred.label,
            "aws_access_key_id",
            Some(cred.access_key_id.clone()),
        );
        ini.set(
            &cred.label,
            "aws_secret_access_key",
            Some(cred.secret_access_key.clone()),
        );
        ini.set(
            &cred.label,
            "aws_session_token",
            Some(cred.session_token.clone()),
        );
        if let Some(expiration) = &cred.expiration {
            ini.set(&cred.label, "expiration", Some(expiration.clone()));
        }
    }

    ini.write(path.to_string_lossy().as_ref())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(path)
}

fn credentials_path() -> Result<PathBuf> {
    let base_dirs =
        BaseDirs::new().context("Unable to determine home directory for credentials file")?;
    Ok(base_dirs.home_dir().join(".aws").join("credentials"))
}

pub fn credentials_valid(label: &str) -> Result<bool> {
    let expiration = read_credentials_entry(label)?;
    let Some(expiration) = expiration else {
        return Ok(false);
    };
    let now = now_datetime()?;
    Ok(expiration.as_nanos() > now.as_nanos())
}

pub fn set_default_profile(label: &str) -> Result<PathBuf> {
    let path = credentials_path()?;
    let mut ini = load_credentials_ini(&path)?;

    let access_key_id = ini
        .get(label, "aws_access_key_id")
        .ok_or_else(|| anyhow!("Missing aws_access_key_id for {}", label))?;
    let secret_access_key = ini
        .get(label, "aws_secret_access_key")
        .ok_or_else(|| anyhow!("Missing aws_secret_access_key for {}", label))?;
    let session_token = ini
        .get(label, "aws_session_token")
        .ok_or_else(|| anyhow!("Missing aws_session_token for {}", label))?;
    let expiration = ini.get(label, "expiration");

    ini.set("default", "aws_access_key_id", Some(access_key_id));
    ini.set("default", "aws_secret_access_key", Some(secret_access_key));
    ini.set("default", "aws_session_token", Some(session_token));
    if let Some(expiration) = expiration {
        ini.set("default", "expiration", Some(expiration));
    }

    ini.write(path.to_string_lossy().as_ref())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(path)
}

pub fn read_credentials_status(labels: &[String]) -> Result<HashMap<String, CredentialsStatus>> {
    let path = credentials_path()?;
    let mut status = HashMap::new();
    if !path.exists() {
        for label in labels {
            status.insert(
                label.clone(),
                CredentialsStatus {
                    expiration: None,
                },
            );
        }
        return Ok(status);
    }

    let ini = load_credentials_ini(&path)?;
    let now = now_datetime()?;
    for label in labels {
        let expiration = ini
            .get(label, "expiration")
            .and_then(|value| parse_expiration(&value));
        status.insert(
            label.clone(),
            CredentialsStatus {
                expiration,
            },
        );
    }
    Ok(status)
}

pub fn detect_default_profile(labels: &[String]) -> Result<Option<String>> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let ini = load_credentials_ini(&path)?;
    let default_access = ini.get("default", "aws_access_key_id");
    let default_secret = ini.get("default", "aws_secret_access_key");
    let default_token = ini.get("default", "aws_session_token");

    let Some(default_access) = default_access else { return Ok(None); };
    let Some(default_secret) = default_secret else { return Ok(None); };
    let Some(default_token) = default_token else { return Ok(None); };

    for label in labels {
        let access = ini.get(label, "aws_access_key_id");
        let secret = ini.get(label, "aws_secret_access_key");
        let token = ini.get(label, "aws_session_token");
        if access.as_deref() == Some(default_access.as_str())
            && secret.as_deref() == Some(default_secret.as_str())
            && token.as_deref() == Some(default_token.as_str())
        {
            return Ok(Some(label.clone()));
        }
    }

    Ok(None)
}

fn read_credentials_entry(label: &str) -> Result<Option<DateTime>> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let ini = load_credentials_ini(&path)?;

    let expiration = ini
        .get(label, "expiration")
        .and_then(|value| parse_expiration(&value));

    Ok(expiration)
}

fn parse_expiration(value: &str) -> Option<DateTime> {
    DateTime::from_str(value, Format::DateTimeWithOffset)
        .or_else(|_| DateTime::from_str(value, Format::DateTime))
        .ok()
}

fn now_datetime() -> Result<DateTime> {
    Ok(DateTime::from_secs(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time before Unix epoch")?
            .as_secs() as i64,
    ))
}

fn load_credentials_ini(path: &PathBuf) -> Result<Ini> {
    let mut ini = Ini::new();
    if path.exists() {
        ini.load(path.to_string_lossy().as_ref())
            .map_err(|err| anyhow!(err))
            .context("Failed to read existing credentials file")?;
    }
    Ok(ini)
}
