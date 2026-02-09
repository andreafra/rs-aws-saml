use crate::config::{AwsAccount, LoginProfile};
use crate::AppState;
use gpui::{div, Context, FontWeight, ParentElement, Styled};
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::group_box::{GroupBox, GroupBoxVariants};
use gpui_component::{h_flex, Disableable, IconName, StyledExt};
use gpui_component::spinner::Spinner;

pub(crate) fn account_card(
    account: &AwsAccount,
    expiration: String,
    index: usize,
    label: String,
    login: LoginProfile,
    accounts_list: Vec<AwsAccount>,
    default_profile: Option<&str>,
    auth_in_progress: bool,
    cx: &mut Context<AppState>,
) -> GroupBox {
    let mut group = GroupBox::new();

    let is_active_profile = default_profile == Some(account.label.as_str());

    if is_active_profile {
        group = group.fill()
    } else {
        group = group.outline()
    }

    let group_items = div()
        .v_flex()
        .gap_0()
        .child(
            div().font_weight(FontWeight::BOLD).text_2xl().child(label.clone())
        )
        .child(
            h_flex()
                .gap_2()
                .child(div().font_weight(FontWeight::SEMIBOLD).child("Account:"))
                .child(div().child(account.account.clone())),
        )
        .child(
            h_flex()
                .gap_2()
                .child(div().font_weight(FontWeight::SEMIBOLD).child("Role:"))
                .child(div().child(account.iam_role.clone())),
        )
        .child(
            h_flex()
                .gap_2()
                .child(
                    div()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("SAML Provider:"),
                )
                .child(div().child(account.saml_provider.clone())),
        )
        .child({
            let status_value = if auth_in_progress {
                div().child(Spinner::new())
            } else {
                div().child(expiration)
            };
            h_flex()
                .gap_2()
                .child(div().font_weight(FontWeight::SEMIBOLD).child("Status:"))
                .child(status_value)
        })
        .child(
            div().h_flex().gap_2().child(
                Button::new(("set-default", index))
                    .mt_2()
                    .icon(IconName::Star)
                    .primary()
                    .label("Activate")
                    .cursor_pointer()
                    .disabled(is_active_profile)
                    .on_click(cx.listener(move |this, _event, window, cx| {
                        this.set_default_profile_action(
                            label.clone(),
                            login.clone(),
                            accounts_list.clone(),
                            window,
                            cx,
                        );
                    })),
            ),
        );

    group.child(group_items)
}
