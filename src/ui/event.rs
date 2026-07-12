use crate::core::event::TraceEvent;
use crate::ui::Panel;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Event detail panel — shows the selected event's full data.
pub struct EventView {
    event: Option<TraceEvent>,
}

impl EventView {
    pub fn new() -> Self {
        Self { event: None }
    }

    pub fn set_event(&mut self, event: TraceEvent) {
        self.event = Some(event);
    }
}

impl Panel for EventView {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let content = match &self.event {
            Some(ev) => {
                format!(
                    "ID:     {}\n\
                     Kind:   {}\n\
                     Source: {:?}\n\
                     Status: {:?}\n\
                     Effect: {:?}\n\
                     Start:  {}\n\
                     End:    {}\n\
                     Dur:    {}ms\n\
                     Meta:   {}",
                    ev.id,
                    ev.kind,
                    ev.source,
                    ev.status,
                    ev.side_effect,
                    ev.started_at.format("%H:%M:%S.%3f"),
                    ev.ended_at
                        .map(|t| t.format("%H:%M:%S.%3f").to_string())
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    ev.duration_ms
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    serde_json::to_string_pretty(&ev.metadata)
                        .unwrap_or_else(|_| "(invalid)".to_string()),
                )
            }
            None => "Select an event to inspect".to_string(),
        };

        let para = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL).title("Event Details"));
        frame.render_widget(para, area);
    }
}
