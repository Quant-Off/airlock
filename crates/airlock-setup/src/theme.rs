use cliclack::{Theme, ThemeState};
use console::{Emoji, Style};

// xterm 256색 173은 Claude Code 계열의 웜 코랄과 가장 가까운 값
const ACCENT: u8 = 173;

pub(crate) fn accent() -> Style {
    Style::new().color256(ACCENT)
}

pub(crate) fn title() -> String {
    format!(
        "{} {}",
        accent().reverse().bold().apply_to(" airlock "),
        Style::new().dim().apply_to("setup")
    )
}

pub(crate) fn command(text: &str) -> String {
    accent().bold().apply_to(text).to_string()
}

#[derive(Debug)]
pub struct AirlockTheme;

impl Theme for AirlockTheme {
    fn bar_color(&self, state: &ThemeState) -> Style {
        match state {
            ThemeState::Active => accent(),
            ThemeState::Cancel => Style::new().red(),
            ThemeState::Submit => Style::new().bright().black(),
            ThemeState::Error(_) => Style::new().yellow(),
        }
    }

    fn state_symbol_color(&self, state: &ThemeState) -> Style {
        match state {
            ThemeState::Submit => accent(),
            _ => self.bar_color(state),
        }
    }

    fn radio_symbol(&self, state: &ThemeState, selected: bool) -> String {
        match state {
            ThemeState::Active if selected => accent().apply_to(Emoji("●", ">")).to_string(),
            ThemeState::Active => Style::new().dim().apply_to(Emoji("○", " ")).to_string(),
            _ => String::new(),
        }
    }

    fn checkbox_symbol(&self, state: &ThemeState, selected: bool, active: bool) -> String {
        match state {
            ThemeState::Active | ThemeState::Error(_) if selected => {
                accent().apply_to(Emoji("◼", "[+]")).to_string()
            }
            ThemeState::Active | ThemeState::Error(_) if active => {
                accent().apply_to(Emoji("◻", "[.]")).to_string()
            }
            ThemeState::Active | ThemeState::Error(_) => {
                Style::new().dim().apply_to(Emoji("◻", "[ ]")).to_string()
            }
            _ => String::new(),
        }
    }

    fn active_symbol(&self) -> String {
        accent().apply_to(Emoji("◆", "*")).to_string()
    }

    fn submit_symbol(&self) -> String {
        accent().apply_to(Emoji("◇", "o")).to_string()
    }

    fn info_symbol(&self) -> String {
        accent().apply_to(Emoji("●", "*")).to_string()
    }

    fn format_progress_start(&self, template: &str, grouped: bool, last: bool) -> String {
        let space = if grouped { " " } else { "  " };
        self.format_progress_with_state(
            &format!("{{spinner:.{ACCENT}}}{space}{template}"),
            grouped,
            last,
            &ThemeState::Active,
        )
    }
}
