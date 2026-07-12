use crate::ui::Panel;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Run comparison panel — shows differences between two runs.
pub struct DiffView;

impl Default for DiffView {
    fn default() -> Self {
        Self::new()
    }
}

impl DiffView {
    pub fn new() -> Self {
        Self
    }
}

impl Panel for DiffView {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let para = Paragraph::new("Run comparison \u{2014} select two runs to diff")
            .block(Block::default().borders(Borders::ALL).title("Diff"));
        frame.render_widget(para, area);
    }
}
