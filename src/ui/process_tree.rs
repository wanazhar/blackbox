use crate::ui::Panel;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Process tree panel — shows the hierarchy of commands launched.
pub struct ProcessTreeView;

impl Default for ProcessTreeView {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTreeView {
    pub fn new() -> Self {
        Self
    }
}

impl Panel for ProcessTreeView {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let para = Paragraph::new("Process tree \u{2014} shown when processes are captured")
            .block(Block::default().borders(Borders::ALL).title("Process Tree"));
        frame.render_widget(para, area);
    }
}
