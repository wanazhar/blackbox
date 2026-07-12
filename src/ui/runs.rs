use crate::core::run::Run;
use crate::ui::Panel;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use ratatui::Frame;

/// Runs list panel — shows all recorded runs.
pub struct RunsView {
    runs: Vec<Run>,
    state: ListState,
}

impl RunsView {
    pub fn new(runs: Vec<Run>) -> Self {
        let mut state = ListState::default();
        if !runs.is_empty() {
            state.select(Some(0));
        }
        Self { runs, state }
    }
}

impl Panel for RunsView {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .runs
            .iter()
            .map(|run| {
                let name = run.name.as_deref().unwrap_or("(unnamed)");
                let status = match &run.status {
                    crate::core::run::RunStatus::Succeeded => "\u{2713}",
                    crate::core::run::RunStatus::Failed => "\u{2717}",
                    crate::core::run::RunStatus::Running => "\u{25CF}",
                    _ => "?",
                };
                let label = format!("{} {}  {}", status, &run.id[..8], name);
                ListItem::new(Span::raw(label))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Runs"))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        let mut state = self.state.clone();
        frame.render_stateful_widget(list, area, &mut state);
    }
}
