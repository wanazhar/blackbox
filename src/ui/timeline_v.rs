use crate::core::event::TraceEvent;
use crate::ui::Panel;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Timeline panel — shows chronological event sequence.
pub struct TimelineView {
    events: Vec<TraceEvent>,
}

impl TimelineView {
    pub fn new(events: Vec<TraceEvent>) -> Self {
        Self { events }
    }
}

impl Panel for TimelineView {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let text: Vec<String> = self
            .events
            .iter()
            .map(|ev| {
                let offset = ev.started_at.format("%H:%M:%S").to_string();
                format!("{}  {}  {:?}", offset, ev.kind, ev.status)
            })
            .collect();

        let content = text.join("\n");
        let para =
            Paragraph::new(content).block(Block::default().borders(Borders::ALL).title("Timeline"));
        frame.render_widget(para, area);
    }
}
