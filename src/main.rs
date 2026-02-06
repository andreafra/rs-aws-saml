mod config;
mod aws;
mod headless;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use async_channel::{Receiver, Sender};
use gpui::*;
use gpui_component::checkbox::Checkbox;
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::select::{SearchableVec, Select, SelectEvent, SelectState};
use gpui_component::{button::*, *};
use gpui_component::IndexPath;

use crate::config::{
    config_path, load_config, load_config_text, parse_config, save_config_text, AwsAccount, Config,
    LoginProfile,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Profiles,
    Config,
}

enum AuthEvent {
    Status(String),
    Finished {
        profile: String,
        accounts: usize,
    },
    Failed { profile: String, error: String },
    CredentialsUpdated { labels: Vec<String> },
}

pub struct AppState {
    config: Result<Config, String>,
    status: String,
    status_log: Vec<String>,
    status_tx: Sender<AuthEvent>,
    headless: bool,
    view: ViewMode,
    config_editor: Entity<InputState>,
    aws_select: Entity<SelectState<SearchableVec<String>>>,
    default_profile: Option<String>,
    account_status: HashMap<String, aws::CredentialsStatus>,
    config_path: PathBuf,
    config_error: Option<String>,
    config_dirty: bool,
    _editor_subscription: Subscription,
    _select_subscription: Subscription,
}

impl AppState {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let config = load_config().map_err(|err| err.to_string());
        let config_path = config_path();
        let mut config_error = None;
        let config_text = match load_config_text() {
            Ok(contents) => contents,
            Err(err) => {
                config_error = Some(err.to_string());
                String::new()
            }
        };
        if let Err(message) = &config {
            if config_error.is_none() {
                config_error = Some(message.clone());
            }
        }

        let (status_tx, status_rx) = async_channel::unbounded();
        start_status_listener(cx, status_rx);

        let config_editor = cx.new(|cx| InputState::new(window, cx).multi_line(true));
        config_editor.update(cx, |state, cx| {
            state.set_value(config_text, window, cx);
        });

        let editor_subscription = cx.subscribe_in(
            &config_editor,
            window,
            |this: &mut AppState, _state, event: &InputEvent, _window, cx| {
                if let InputEvent::Change = event {
                    if !this.config_dirty {
                        this.status = "Config modified".to_string();
                    }
                    this.config_dirty = true;
                    cx.notify();
                }
            },
        );

        let aws_labels = match &config {
            Ok(config) => config
                .aws
                .accounts
                .iter()
                .map(|account| account.label.clone())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        let account_status = aws::read_credentials_status(&aws_labels).unwrap_or_default();
        let default_profile = aws::detect_default_profile(&aws_labels).ok().flatten();
        let selected_index = default_profile
            .as_ref()
            .and_then(|label| aws_labels.iter().position(|item| item == label))
            .map(|idx| IndexPath::default().row(idx));
        let aws_select = cx.new(|cx| {
            SelectState::new(SearchableVec::new(aws_labels), selected_index, window, cx)
                .searchable(true)
        });
        let select_subscription = cx.subscribe_in(
            &aws_select,
            window,
            |this: &mut AppState, _state, event: &SelectEvent<SearchableVec<String>>, _window, cx| {
                if let SelectEvent::Confirm(Some(value)) = event {
                    this.default_profile = Some(value.clone());
                    this.push_status(format!("Default profile selected: {}", value));
                    cx.notify();
                }
            },
        );

        Self {
            config,
            status: "Ready".to_string(),
            status_log: Vec::new(),
            status_tx,
            headless: true,
            view: ViewMode::Profiles,
            config_editor,
            aws_select,
            default_profile,
            account_status,
            config_path,
            config_error,
            config_dirty: false,
            _editor_subscription: editor_subscription,
            _select_subscription: select_subscription,
        }
    }

    fn refresh_aws_select(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let labels = match &self.config {
            Ok(config) => config
                .aws
                .accounts
                .iter()
                .map(|account| account.label.clone())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };

        if self.default_profile.is_none() {
            self.default_profile = aws::detect_default_profile(&labels).ok().flatten();
        }

        let selected_index = self
            .default_profile
            .as_ref()
            .and_then(|label| labels.iter().position(|item| item == label))
            .map(|idx| IndexPath::default().row(idx));

        if selected_index.is_none() {
            self.default_profile = None;
        }

        if let Ok(status) = aws::read_credentials_status(&labels) {
            self.account_status = status;
        }

        let aws_select = cx.new(|cx| {
            SelectState::new(SearchableVec::new(labels), selected_index, window, cx).searchable(true)
        });
        let select_subscription = cx.subscribe_in(
            &aws_select,
            window,
            |this: &mut AppState, _state, event: &SelectEvent<SearchableVec<String>>, _window, cx| {
                if let SelectEvent::Confirm(Some(value)) = event {
                    this.default_profile = Some(value.clone());
                    this.push_status(format!("Default profile selected: {}", value));
                    cx.notify();
                }
            },
        );

        self.aws_select = aws_select;
        self._select_subscription = select_subscription;
    }

    fn format_account_expiration(&self, label: &str) -> String {
        let Some(status) = self.account_status.get(label) else {
            return "no credentials".to_string();
        };
        let Some(expiration) = &status.expiration else {
            return "no expiration".to_string();
        };
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return "unknown".to_string();
        };
        let now_secs = now.as_secs() as i64;
        let exp_secs = expiration.secs();
        if exp_secs <= now_secs {
            return "expired".to_string();
        }
        let remaining = (exp_secs - now_secs) as u64;
        if remaining >= 3600 {
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            format!("expires in {}h{}m", hours, minutes)
        } else {
            let minutes = remaining / 60;
            let seconds = remaining % 60;
            format!("expires in {}m{}s", minutes, seconds)
        }
    }

    fn push_status(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.status = message.clone();
        self.status_log.push(message);
        if self.status_log.len() > 8 {
            let overflow = self.status_log.len() - 8;
            self.status_log.drain(0..overflow);
        }
    }

    fn apply_event(&mut self, event: AuthEvent) {
        match event {
            AuthEvent::Status(message) => self.push_status(message),
            AuthEvent::Finished {
                profile,
                accounts,
            } => {
                self.push_status(format!(
                    "Completed {} ({} accounts)",
                    profile, accounts
                ));
            }
            AuthEvent::Failed { profile, error } => {
                self.push_status(format!("Auth failed for {}: {}", profile, error));
            }
            AuthEvent::CredentialsUpdated { labels } => {
                if let Ok(status) = aws::read_credentials_status(&labels) {
                    self.account_status = status;
                }
            }
        }
    }
}

impl Render for AppState {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut content = div()
            .v_flex()
            .gap_3()
            .size_full()
            .child("AWS SAML Auth")
            .child(
                div()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .child(
                        Button::new("view-profiles")
                            .label("Profiles")
                            .with_variant(if self.view == ViewMode::Profiles {
                                ButtonVariant::Primary
                            } else {
                                ButtonVariant::Ghost
                            })
                            .on_click(cx.listener(|this, _event, _window, _cx| {
                                this.view = ViewMode::Profiles;
                            })),
                    )
                    .child(
                        Button::new("view-config")
                            .label("Edit Config")
                            .with_variant(if self.view == ViewMode::Config {
                                ButtonVariant::Primary
                            } else {
                                ButtonVariant::Ghost
                            })
                            .on_click(cx.listener(|this, _event, _window, _cx| {
                                this.view = ViewMode::Config;
                            })),
                    )
                    .child(
                        Checkbox::new("headless")
                            .label("Headless (off to debug)")
                            .checked(self.headless)
                            .on_click(cx.listener(|this, checked, _window, _cx| {
                                this.headless = *checked;
                                if this.headless {
                                    this.push_status("Headless enabled");
                                } else {
                                    this.push_status("Headless disabled");
                                }
                            })),
                    ),
            )
            .child(format!("Status: {}", self.status));

        if !self.status_log.is_empty() {
            let mut log = div().v_flex().gap_1();
            for entry in self.status_log.iter().rev() {
                log = log.child(entry.clone());
            }
            content = content.child(log);
        }

        match self.view {
            ViewMode::Profiles => match &self.config {
                Ok(config) => {
                    content = content.child(format!("Login profile: {}", config.login.name));
                    if config.aws.accounts.is_empty() {
                        content = content.child("No AWS accounts configured.");
                    } else {
                        let mut accounts = div().v_flex().gap_1();
                        for account in &config.aws.accounts {
                            let expiration = self.format_account_expiration(&account.label);
                            accounts = accounts.child(format!(
                                "{} ({} / {}) - {}",
                                account.label, account.account, account.iam_role, expiration
                            ));
                        }
                        content = content.child(accounts);
                    }

                    let login = config.login.clone();
                    let accounts = config.aws.accounts.clone();
                    content = content.child(
                        Button::new("auth-all")
                            .primary()
                            .label("Authenticate And Assume Roles")
                            .on_click(cx.listener(move |this, _event, _window, _cx| {
                                this.push_status(format!(
                                    "Authenticating {}...",
                                    login.name.clone()
                                ));
                                start_auth(
                                    login.clone(),
                                    accounts.clone(),
                                    this.headless,
                                    this.status_tx.clone(),
                                    this.default_profile.clone(),
                                );
                            })),
                    );

                    let login = config.login.clone();
                    let accounts = config.aws.accounts.clone();
                    content = content.child(
                        div()
                            .h_flex()
                            .gap_2()
                            .items_center()
                            .child("Default profile:")
                            .child(Select::new(&self.aws_select).placeholder("Select profile"))
                            .child(
                                Button::new("set-default")
                                    .label("Set Default")
                                    .on_click(cx.listener(move |this, _event, _window, _cx| {
                                        let Some(label) = this.default_profile.clone() else {
                                            this.push_status("Select a default profile first");
                                            return;
                                        };

                                        match aws::credentials_valid(&label) {
                                            Ok(true) => match aws::set_default_profile(&label) {
                                                Ok(path) => {
                                                    this.push_status(format!(
                                                        "Default profile set to {} ({})",
                                                        label,
                                                        path.display()
                                                    ));
                                                }
                                                Err(err) => {
                                                    this.push_status(format!(
                                                        "Failed to set default profile: {err:?}"
                                                    ));
                                                }
                                            },
                                            Ok(false) | Err(_) => {
                                                this.push_status(format!(
                                                    "Credentials for {} expired or missing; re-authenticating",
                                                    label
                                                ));
                                                start_auth(
                                                    login.clone(),
                                                    accounts.clone(),
                                                    this.headless,
                                                    this.status_tx.clone(),
                                                    Some(label),
                                                );
                                            }
                                        }
                                    })),
                            ),
                    );
                }
                Err(message) => {
                    content = content.child(format!("Config error: {message}"));
                }
            },
            ViewMode::Config => {
                content = content
                    .child(format!("Editing: {}", self.config_path.display()))
                    .child(if self.config_dirty {
                        "Unsaved changes"
                    } else {
                        "Saved"
                    });

                if let Some(error) = &self.config_error {
                    content = content.child(format!("Config error: {error}"));
                }

                content = content.child(
                    div().size_full().child(Input::new(&self.config_editor).h_full()),
                );

                content = content.child(
                    div()
                        .h_flex()
                        .gap_2()
                        .child(
                            Button::new("save-config")
                                .primary()
                                .label("Save")
                                .on_click(cx.listener(|this, _event, window, cx| {
                                    let contents = this.config_editor.read(cx).value();
                                    match save_config_text(contents.as_str()) {
                                        Ok(path) => {
                                            this.config_path = path;
                                            match parse_config(contents.as_str()) {
                                                Ok(config) => {
                                                    this.config = Ok(config);
                                                    this.config_error = None;
                                                    this.config_dirty = false;
                                                    this.refresh_aws_select(window, cx);
                                                    this.push_status("Config saved");
                                                }
                                                Err(err) => {
                                                    this.config = Err(err.to_string());
                                                    this.config_error = Some(err.to_string());
                                                    this.push_status(
                                                        "Config saved, but parsing failed",
                                                    );
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            this.config_error = Some(err.to_string());
                                            this.push_status("Config save failed");
                                        }
                                    }
                                })),
                        )
                        .child(
                            Button::new("reload-config")
                                .ghost()
                                .label("Reload")
                                .on_click(cx.listener(|this, _event, window, cx| {
                                    match load_config_text() {
                                        Ok(contents) => {
                                            let parse_result = parse_config(contents.as_str());
                                            this.config_editor.update(cx, |state, cx| {
                                                state.set_value(contents.clone(), window, cx);
                                            });
                                            match parse_result {
                                                Ok(config) => {
                                                    this.config = Ok(config);
                                                    this.config_error = None;
                                                    this.refresh_aws_select(window, cx);
                                                }
                                                Err(err) => {
                                                    this.config = Err(err.to_string());
                                                    this.config_error = Some(err.to_string());
                                                }
                                            }
                                            this.config_dirty = false;
                                            this.push_status("Config reloaded");
                                        }
                                        Err(err) => {
                                            this.config_error = Some(err.to_string());
                                            this.push_status("Config reload failed");
                                        }
                                    }
                                })),
                        ),
                );
            }
        }

        content
    }
}

fn start_status_listener(cx: &mut Context<AppState>, status_rx: Receiver<AuthEvent>) {
    cx.spawn(move |this: gpui::WeakEntity<AppState>, cx: &mut gpui::AsyncApp| {
        let app = cx.clone();
        async move {
            let mut app = app;
            while let Ok(event) = status_rx.recv().await {
                if let Some(view) = this.upgrade() {
                    let _ = view.update(&mut app, |this, cx| {
                        this.apply_event(event);
                        cx.notify();
                    });
                } else {
                    break;
                }
            }
        }
    })
    .detach();
}

fn start_auth(
    login: LoginProfile,
    accounts: Vec<AwsAccount>,
    headless: bool,
    status_tx: Sender<AuthEvent>,
    default_profile: Option<String>,
) {
    std::thread::spawn(move || {
        let send_status = |tx: &Sender<AuthEvent>, message: &str| {
            let _ = tx.send_blocking(AuthEvent::Status(message.to_string()));
        };
        send_status(&status_tx, "Starting auth flow");

        let status_tx_login = status_tx.clone();
        let login_result = headless::run_profile(&login, headless, |message| {
            let _ = status_tx_login.send_blocking(AuthEvent::Status(message.to_string()));
        });

        match login_result {
            Ok(result) => {
                let size = result.saml_response.len();
                send_status(&status_tx, &format!("Captured SAMLResponse ({} bytes)", size));

                if accounts.is_empty() {
                    let _ = status_tx.send_blocking(AuthEvent::Finished {
                        profile: login.name.clone(),
                        accounts: 0,
                    });
                    return;
                }

                let status_tx_aws = status_tx.clone();
                let sts_result = aws::assume_roles_with_saml(
                    &result.saml_response,
                    &accounts,
                    |message| {
                        let _ =
                            status_tx_aws.send_blocking(AuthEvent::Status(message.to_string()));
                    },
                );

                match sts_result {
                    Ok(creds) => match aws::write_credentials(&creds) {
                        Ok(path) => {
                            send_status(
                                &status_tx,
                                &format!("Credentials written to {}", path.display()),
                            );
                            if let Some(label) = default_profile.clone() {
                                match aws::set_default_profile(&label) {
                                    Ok(default_path) => {
                                        send_status(
                                            &status_tx,
                                            &format!(
                                                "Default profile set to {} ({})",
                                                label,
                                                default_path.display()
                                            ),
                                        );
                                    }
                                    Err(err) => {
                                        send_status(
                                            &status_tx,
                                            &format!(
                                                "Failed to set default profile: {err:?}"
                                            ),
                                        );
                                    }
                                }
                            }

                            let labels = accounts.iter().map(|a| a.label.clone()).collect();
                            let _ = status_tx.send_blocking(AuthEvent::CredentialsUpdated { labels });
                            let _ = status_tx.send_blocking(AuthEvent::Finished {
                                profile: login.name.clone(),
                                accounts: creds.len(),
                            });
                        }
                        Err(err) => {
                            let _ = status_tx.send_blocking(AuthEvent::Failed {
                                profile: login.name.clone(),
                                error: format!("Failed to write credentials: {err:?}"),
                            });
                        }
                    },
                    Err(err) => {
                        let _ = status_tx.send_blocking(AuthEvent::Failed {
                            profile: login.name.clone(),
                            error: format!("STS exchange failed: {err:?}"),
                        });
                    }
                }
            }
            Err(err) => {
                let _ = status_tx.send_blocking(AuthEvent::Failed {
                    profile: login.name.clone(),
                    error: format!("{err:?}"),
                });
                eprintln!("Auth failed for {}: {err:?}", login.name);
            }
        }
    });
}

fn main() {
    let app = Application::new().with_assets(gpui_component_assets::Assets);

    app.run(move |cx| {
        gpui_component::init(cx);

        cx.spawn(async move |cx| {
            cx.open_window(WindowOptions::default(), |window, cx| {
                let view = cx.new(|cx| AppState::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            })?;

            Ok::<_, anyhow::Error>(())
        })
        .detach();
    });
}
