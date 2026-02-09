use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use headless_chrome::{
    protocol::cdp::Fetch::{events::RequestPausedEvent, RequestPattern, RequestStage}, Browser, LaunchOptionsBuilder,
    Tab,
};
use serde_json::Value as JsonValue;
use totp_rs::{Algorithm, Secret, TOTP};
use url::form_urlencoded;

use crate::config::LoginProfile;

pub struct AuthResult {
    pub saml_response: String,
}

pub fn run_profile(
    profile: &LoginProfile,
    headless: bool,
    mut on_status: impl FnMut(&str),
) -> Result<AuthResult> {
    on_status("Launching browser");
    let browser = Browser::new(
        LaunchOptionsBuilder::default()
            .headless(headless)
            .build()
            .context("Failed to build Chrome launch options")?,
    )
    .context("Failed to launch headless Chrome")?;

    let tab = browser.new_tab().context("Failed to open new tab")?;
    let (saml_sender, saml_rx) = std::sync::mpsc::channel::<String>();
    let saml_url = "https://signin.aws.amazon.com/saml".to_string();

    tab.enable_fetch(
        Some(&[RequestPattern {
            url_pattern: Some(saml_url.clone()),
            resource_Type: None,
            request_stage: Some(RequestStage::Request),
        }]),
        None,
    )
    .context("Failed to enable request interception")?;

    tab.enable_request_interception(std::sync::Arc::new(
        move |_transport, _session, event: RequestPausedEvent| {
        let request = &event.params.request;
        if request.url == saml_url && request.method.eq_ignore_ascii_case("POST") {
            if let Some(post_data) = request.post_data.as_deref() {
                if let Some(saml_response) = extract_saml_response_from_post_data(post_data) {
                    let _ = saml_sender.send(saml_response);
                }
            }
        }
        headless_chrome::browser::tab::RequestPausedDecision::Continue(None)
    },
    ))?;

    on_status("Loading login page");
    tab.navigate_to(&profile.login_url)
        .with_context(|| format!("Failed to navigate to {}", profile.login_url))?;
    tab.wait_until_navigated()
        .context("Navigation did not complete")?;

    if let Some(selector) = profile.selectors.username.as_deref() {
        on_status("Filling username");
        fill_input(&tab, selector, &profile.username)?;
    }

    if let Some(selector) = profile.selectors.password.as_deref() {
        on_status("Filling password");
        fill_input(&tab, selector, &profile.password)?;
    }

    if let Some(selector) = profile.selectors.submit.as_deref() {
        on_status("Submitting login form");
        click(&tab, selector)?;
    }

    if let Some(otp_selector) = profile.selectors.otp.as_deref() {
        on_status("Waiting for OTP input");
        let otp = generate_totp(profile)?;
        wait_for_element(
            &tab,
            otp_selector,
            Duration::from_secs(profile.waits.otp_timeout_secs),
        )?;
        on_status("Filling OTP");
        fill_input(&tab, otp_selector, &otp)?;

        if let Some(selector) = profile.selectors.otp_submit.as_deref() {
            on_status("Submitting OTP");
            click(&tab, selector)?;
        }
    }

    let saml_selector = profile
        .selectors
        .saml_response
        .as_deref()
        .unwrap_or("input[name=\"SAMLResponse\"]");
    on_status("Waiting for SAMLResponse");
    let saml_response = match saml_rx.recv_timeout(Duration::from_secs(profile.waits.saml_timeout_secs)) {
        Ok(value) => value,
        Err(_) => {
            on_status("Network capture timed out, falling back to DOM");
            wait_for_input_value(
                &tab,
                saml_selector,
                Duration::from_secs(profile.waits.saml_timeout_secs),
            )?
        }
    };
    on_status("Captured SAMLResponse");

    Ok(AuthResult { saml_response })
}

fn extract_saml_response_from_post_data(post_data: &str) -> Option<String> {
    for (key, value) in form_urlencoded::parse(post_data.as_bytes()) {
        if key == "SAMLResponse" {
            return Some(value.into_owned());
        }
    }
    None
}

fn fast_set_value(
    element: &headless_chrome::browser::tab::element::Element<'_>,
    value: &str,
) -> Result<()> {
    let script = r#"
        function(value) {
            const input = this;
            try { input.focus(); } catch (_) {}
            const proto = Object.getPrototypeOf(input);
            const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
            if (descriptor && descriptor.set) {
                descriptor.set.call(input, value);
            } else {
                input.value = value;
            }
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
        }
    "#;
    element.call_js_fn(script, vec![JsonValue::String(value.to_string())], false)?;
    Ok(())
}

fn fill_input(tab: &Tab, selector: &str, value: &str) -> Result<()> {
    let element = tab
        .wait_for_element(selector)
        .with_context(|| format!("Failed to find element {}", selector))?;
    if fast_set_value(&element, value).is_err() {
        element.click().ok();
        element
            .type_into(value)
            .with_context(|| format!("Failed to type into {}", selector))?;
    }
    Ok(())
}

fn click(tab: &Tab, selector: &str) -> Result<()> {
    let element = tab
        .wait_for_element(selector)
        .with_context(|| format!("Failed to find element {}", selector))?;
    element
        .click()
        .with_context(|| format!("Failed to click {}", selector))?;
    Ok(())
}

fn wait_for_element(tab: &Tab, selector: &str, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if tab.find_element(selector).is_ok() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "Timed out waiting for element {} after {:?}",
                selector,
                timeout
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_input_value(tab: &Tab, selector: &str, timeout: Duration) -> Result<String> {
    let start = Instant::now();
    loop {
        if let Ok(element) = tab.find_element(selector) {
            if let Ok(Some(value)) = element.get_attribute_value("value") {
                if !value.trim().is_empty() {
                    return Ok(value);
                }
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "Timed out waiting for SAMLResponse at {} after {:?}",
                selector,
                timeout
            ));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn generate_totp(profile: &LoginProfile) -> Result<String> {
    let secret = profile
        .totp_secret
        .clone()
        .context("Profile is missing totp_secret")?;
    let encoded_secret = Secret::Encoded(secret);
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        encoded_secret.to_bytes().unwrap(),
    )
    .context("Invalid TOTP RFC param")?;
    let code = totp.generate_current().context("Failed to generate TOTP")?;
    Ok(code)
}
