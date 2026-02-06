use std::{path::PathBuf};

use anyhow::{Context, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use aws_sdk_sts::Client;
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

    let mut ini = Ini::new();
    if path.exists() {
        ini.load(path.to_string_lossy().as_ref())
            .map_err(|err| anyhow::anyhow!(err))
            .context("Failed to read existing credentials file")?;
    }

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
