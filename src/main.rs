mod aws;
mod config;
mod headless;
mod ui;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_channel::{Receiver, Sender};
use gpui::*;
use gpui_component::IndexPath;
use gpui_component::checkbox::Checkbox;
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::scroll::ScrollableElement;
use gpui_component::select::{SearchableVec, SelectEvent, SelectState};
use gpui_component::{button::*, *};

use crate::config::{
    AwsAccount, Config, LoginProfile, config_path, load_config, load_config_text, parse_config,
    save_config_text,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewMode {
    Profiles,
    Config,
    Settings,
    Logs,
}

enum AuthEvent {
    Status(String),
    Finished { profile: String, accounts: usize },
    Failed { profile: String, error: String },
    CredentialsUpdated { labels: Vec<String> },
}

const AUTH_TIMEOUT: Duration = Duration::from_secs(45);

pub struct AppState {
    config: Result<Config, String>,
    status: String,
    status_log: Vec<String>,
    status_tx: Sender<AuthEvent>,
    headless: bool,
    view: ViewMode,
    auth_in_progress: bool,
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
            |this: &mut AppState,
             _state,
             event: &SelectEvent<SearchableVec<String>>,
             _window,
             cx| {
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
            auth_in_progress: false,
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
            SelectState::new(SearchableVec::new(labels), selected_index, window, cx)
                .searchable(true)
        });
        let select_subscription = cx.subscribe_in(
            &aws_select,
            window,
            |this: &mut AppState,
             _state,
             event: &SelectEvent<SearchableVec<String>>,
             _window,
             cx| {
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
        let timestamp = format_timestamp();
        self.status_log
            .push(format!("[{timestamp}] {message}"));
        if self.status_log.len() > 8 {
            let overflow = self.status_log.len() - 8;
            self.status_log.drain(0..overflow);
        }
    }

    pub(crate) fn set_default_profile_action(
        &mut self,
        label: String,
        login: LoginProfile,
        accounts: Vec<AwsAccount>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.default_profile = Some(label.clone());
        self.aws_select.update(cx, |state, cx| {
            state.set_selected_value(&label, window, cx);
        });

        match aws::credentials_valid(&label) {
            Ok(true) => match aws::set_default_profile(&label) {
                Ok(path) => {
                    self.push_status(format!(
                        "Default profile set to {} ({})",
                        label,
                        path.display()
                    ));
                    if let Ok(status) = aws::read_credentials_status(
                        &accounts.iter().map(|a| a.label.clone()).collect::<Vec<_>>(),
                    ) {
                        self.account_status = status;
                    }
                }
                Err(err) => {
                    self.push_status(format!("Failed to set default profile: {err:?}"));
                }
            },
            Ok(false) | Err(_) => {
                self.push_status(format!(
                    "Credentials for {} expired or missing; re-authenticating",
                    label
                ));
                self.auth_in_progress = true;
                start_auth(
                    login,
                    accounts,
                    self.headless,
                    self.status_tx.clone(),
                    Some(label),
                );
            }
        }
    }

    fn apply_event(&mut self, event: AuthEvent) {
        match event {
            AuthEvent::Status(message) => self.push_status(message),
            AuthEvent::Finished { profile, accounts } => {
                self.auth_in_progress = false;
                self.push_status(format!("Completed {} ({} accounts)", profile, accounts));
            }
            AuthEvent::Failed { profile, error } => {
                self.auth_in_progress = false;
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
        let tabs = ui::tabs::main_tabs(self.view, cx);
        let top_bar = div()
            .v_flex()
            .gap_2()
            .child(
                div()
                    .child("AWS SAML Auth")
                    .font_weight(FontWeight::EXTRA_BOLD)
                    .text_3xl(),
            )
            .child(tabs);

        let mut content = div()
            .v_flex()
            .gap_4()
            .size_full()
            .paddings(Edges::all(px(24.)))
            .child(top_bar);
        // .child(format!("Status: {}", self.status));

        let mut body = div().v_flex().gap_4().flex_1().min_h(px(0.));

        match self.view {
            ViewMode::Profiles => match &self.config {
                Ok(config) => {
                    if config.aws.accounts.is_empty() {
                        body = body.child("No AWS accounts configured.");
                    } else {
                        let mut accounts = div()
                            .v_flex()
                            .gap_3()
                            .flex_1()
                            .min_h(px(100.))
                            .overflow_y_scrollbar();
                        for (index, account) in config.aws.accounts.iter().enumerate() {
                            let expiration = self.format_account_expiration(&account.label);
                            let label = account.label.clone();
                            let login = config.login.clone();
                            let accounts_list = config.aws.accounts.clone();
                            let default_profile = self.default_profile.as_deref();
                            let card = ui::cards::account_card(
                                account,
                                expiration,
                                index,
                                label,
                                login,
                                accounts_list,
                                default_profile,
                                self.auth_in_progress,
                                cx,
                            );
                            accounts = accounts.child(card.mb_2());
                        }
                        body = body.child(accounts);
                    }

                    let login = config.login.clone();
                    let accounts = config.aws.accounts.clone();
                    body = body.child(
                        Button::new("auth-all")
                            .icon(IconName::User)
                            .label("Authenticate And Assume Roles")
                            .disabled(self.auth_in_progress)
                            .on_click(cx.listener(move |this, _event, _window, _cx| {
                                this.push_status(format!(
                                    "Authenticating {}...",
                                    login.name.clone()
                                ));
                                this.auth_in_progress = true;
                                start_auth(
                                    login.clone(),
                                    accounts.clone(),
                                    this.headless,
                                    this.status_tx.clone(),
                                    this.default_profile.clone(),
                                );
                            })),
                    );
                }
                Err(message) => {
                    content = content.child(format!("Config error: {message}"));
                }
            },
            ViewMode::Config => {
                body = body
                    .child(
                        GroupBox::new()
                            .child(
                                div()
                                    .h_flex()
                                    .justify_start()
                                    .gap_2()
                                    .child(IconName::File)
                                    .child(format!(
                                        "Editing {}",
                                        self.config_path
                                            .canonicalize()
                                            .unwrap_or_else(|_| self.config_path.clone())
                                            .display()
                                    ))
                            ),
                    );

                if let Some(error) = &self.config_error {
                    body = body.child(format!("Config error: {error}"));
                }

                body = body.child(
                    div()
                        .size_full()
                        .child(Input::new(&self.config_editor).h_full()),
                );

                body = body.child(
                    div()
                        .h_flex()
                        .gap_2()
                        .child(Button::new("save-config")
                            .primary()
                            .label("Save")
                            .disabled(!self.config_dirty)
                            .on_click(
                            cx.listener(|this, _event, window, cx| {
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
                            }),
                        ))
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
            ViewMode::Settings => {
                body = body.child(
                    GroupBox::new().outline().title("Browser").child(
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
                );
            }
            ViewMode::Logs => {
                let mut log_list = div()
                    .v_flex()
                    .gap_1()
                    .flex_1()
                    .min_h(px(0.))
                    .overflow_y_scrollbar();
                if self.status_log.is_empty() {
                    log_list = log_list.child("No logs yet.");
                } else {
                    for entry in self.status_log.iter().rev() {
                        log_list = log_list.child(entry.clone());
                    }
                }
                body = body.child(log_list);
            }
        }

        content.child(body)
    }
}

fn format_timestamp() -> String {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "??:??:??".to_string();
    };
    let secs = now.as_secs() % 86_400;
    let hours = secs / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn start_status_listener(cx: &mut Context<AppState>, status_rx: Receiver<AuthEvent>) {
    cx.spawn(
        move |this: gpui::WeakEntity<AppState>, cx: &mut gpui::AsyncApp| {
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
        },
    )
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
        let cancelled = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));

        let timeout_tx = status_tx.clone();
        let timeout_login = login.name.clone();
        let timeout_cancelled = Arc::clone(&cancelled);
        let timeout_finished = Arc::clone(&finished);
        std::thread::spawn(move || {
            std::thread::sleep(AUTH_TIMEOUT);
            if timeout_finished.load(Ordering::SeqCst) {
                return;
            }
            timeout_cancelled.store(true, Ordering::SeqCst);
            let _ = timeout_tx.send_blocking(AuthEvent::Failed {
                profile: timeout_login,
                error: format!("Authentication timed out after {}s", AUTH_TIMEOUT.as_secs()),
            });
        });

        let send_status = |tx: &Sender<AuthEvent>, message: &str| {
            if cancelled.load(Ordering::SeqCst) {
                return;
            }
            let _ = tx.send_blocking(AuthEvent::Status(message.to_string()));
        };
        send_status(&status_tx, "Starting auth flow");

        let status_tx_login = status_tx.clone();
        let login_result = headless::run_profile(&login, headless, |message| {
            if cancelled.load(Ordering::SeqCst) {
                return;
            }
            let _ = status_tx_login.send_blocking(AuthEvent::Status(message.to_string()));
        });

        match login_result {
            Ok(result) => {
                if cancelled.load(Ordering::SeqCst) {
                    return;
                }
                let size = result.saml_response.len();
                send_status(
                    &status_tx,
                    &format!("Captured SAMLResponse ({} bytes)", size),
                );

                if accounts.is_empty() {
                    if !cancelled.load(Ordering::SeqCst) {
                        let _ = status_tx.send_blocking(AuthEvent::Finished {
                            profile: login.name.clone(),
                            accounts: 0,
                        });
                    }
                    finished.store(true, Ordering::SeqCst);
                    return;
                }

                let status_tx_aws = status_tx.clone();
                let sts_result =
                    aws::assume_roles_with_saml(&result.saml_response, &accounts, |message| {
                        if cancelled.load(Ordering::SeqCst) {
                            return;
                        }
                        let _ =
                            status_tx_aws.send_blocking(AuthEvent::Status(message.to_string()));
                    });

                match sts_result {
                    Ok(creds) => match aws::write_credentials(&creds) {
                        Ok(path) => {
                            if cancelled.load(Ordering::SeqCst) {
                                return;
                            }
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
                                            &format!("Failed to set default profile: {err:?}"),
                                        );
                                    }
                                }
                            }

                            let labels = accounts.iter().map(|a| a.label.clone()).collect();
                            if !cancelled.load(Ordering::SeqCst) {
                                let _ = status_tx
                                    .send_blocking(AuthEvent::CredentialsUpdated { labels });
                                let _ = status_tx.send_blocking(AuthEvent::Finished {
                                    profile: login.name.clone(),
                                    accounts: creds.len(),
                                });
                            }
                            finished.store(true, Ordering::SeqCst);
                        }
                        Err(err) => {
                            if !cancelled.load(Ordering::SeqCst) {
                                let _ = status_tx.send_blocking(AuthEvent::Failed {
                                    profile: login.name.clone(),
                                    error: format!("Failed to write credentials: {err:?}"),
                                });
                            }
                            finished.store(true, Ordering::SeqCst);
                        }
                    },
                    Err(err) => {
                        if !cancelled.load(Ordering::SeqCst) {
                            let _ = status_tx.send_blocking(AuthEvent::Failed {
                                profile: login.name.clone(),
                                error: format!("STS exchange failed: {err:?}"),
                            });
                        }
                        finished.store(true, Ordering::SeqCst);
                    }
                }
            }
            Err(err) => {
                if !cancelled.load(Ordering::SeqCst) {
                    let _ = status_tx.send_blocking(AuthEvent::Failed {
                        profile: login.name.clone(),
                        error: format!("{err:?}"),
                    });
                }
                finished.store(true, Ordering::SeqCst);
                eprintln!("Auth failed for {}: {err:?}", login.name);
            }
        }
    });
}

fn main() {
    let app = Application::new().with_assets(gpui_component_assets::Assets);

    app.run(move |cx| {
        gpui_component::init(cx);
        let window_bounds = WindowBounds::centered(size(px(600.), px(800.)), cx);

        cx.spawn(async move |cx| {
            let window_options = WindowOptions {
                window_bounds: Some(window_bounds),
                ..WindowOptions::default()
            };
            cx.open_window(window_options, |window, cx| {
                let view = cx.new(|cx| AppState::new(window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            })?;

            Ok::<_, anyhow::Error>(())
        })
        .detach();
    });
}
