pub mod runs;
pub mod timeline_v;
pub mod event;
pub mod diff;
pub mod process_tree;

use ratatui::layout::Rect;
use ratatui::Frame;

/// A TUI panel that can be rendered within a Ratatui layout.
pub trait Panel {
    /// Render this panel into the given frame area.
    fn render(&self, frame: &mut Frame, area: Rect);

    /// Handle an input key event. Return true if handled.
    fn handle_input(&mut self, _key: crossterm::event::KeyEvent) -> bool {
        false
    }
}
