use gpui::Context;
use gpui_component::tab::{Tab, TabBar};

use crate::{AppState, ViewMode};

pub(crate) fn main_tabs(view: ViewMode, cx: &mut Context<AppState>) -> TabBar {
    let selected_index = match view {
        ViewMode::Profiles => 0,
        ViewMode::Config => 1,
        ViewMode::Settings => 2,
        ViewMode::Logs => 3,
    };

    TabBar::new("main-tabs")
        .segmented()
        .selected_index(selected_index)
        .on_click(cx.listener(|this, index, _window, _cx| {
            this.view = match *index {
                0 => ViewMode::Profiles,
                1 => ViewMode::Config,
                2 => ViewMode::Settings,
                _ => ViewMode::Logs,
            };
        }))
        .children([
            Tab::new().label("Profiles"),
            Tab::new().label("Configuration"),
            Tab::new().label("Settings"),
            Tab::new().label("Logs"),
        ])
}
