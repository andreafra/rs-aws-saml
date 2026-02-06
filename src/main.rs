mod config;
mod aws;
mod headless;

use std::path::PathBuf;

use async_channel::{Receiver, Sender};
use gpui::*;
use gpui_component::checkbox::Checkbox;
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::{button::*, *};

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
}

pub struct AppState {
    config: Result<Config, String>,
    status: String,
    status_log: Vec<String>,
    status_tx: Sender<AuthEvent>,
    headless: bool,
    view: ViewMode,
    config_editor: Entity<InputState>,
    config_path: PathBuf,
    config_error: Option<String>,
    config_dirty: bool,
    _subscriptions: Vec<Subscription>,
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

        let subscriptions = vec![cx.subscribe_in(
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
        )];

        Self {
            config,
            status: "Ready".to_string(),
            status_log: Vec::new(),
            status_tx,
            headless: true,
            view: ViewMode::Profiles,
            config_editor,
            config_path,
            config_error,
            config_dirty: false,
            _subscriptions: subscriptions,
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
                    if config.profiles.accounts.is_empty() {
                        content = content.child("No AWS accounts configured.");
                    } else {
                        let mut accounts = div().v_flex().gap_1();
                        for account in &config.profiles.accounts {
                            accounts = accounts.child(format!(
                                "{} ({} / {})",
                                account.label, account.account, account.iam_role
                            ));
                        }
                        content = content.child(accounts);
                    }

                    let login = config.login.clone();
                    let accounts = config.profiles.accounts.clone();
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
                                );
                            })),
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
                                .on_click(cx.listener(|this, _event, _window, cx| {
                                    let contents = this.config_editor.read(cx).value();
                                    match save_config_text(contents.as_str()) {
                                        Ok(path) => {
                                            this.config_path = path;
                                            match parse_config(contents.as_str()) {
                                                Ok(config) => {
                                                    this.config = Ok(config);
                                                    this.config_error = None;
                                                    this.config_dirty = false;
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
                                &format!(
                                "Credentials written to {}",
                                path.display()
                            ),
                            );
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
