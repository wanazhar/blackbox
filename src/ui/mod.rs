pub mod event;
pub mod runs;
pub mod timeline_v;
pub mod tui;

use ratatui::layout::Rect;
use ratatui::Frame;

#[allow(dead_code)] // L-08: trait used only via impl blocks; no dyn Panel or trait bounds yet
/// A TUI panel that can be rendered within a Ratatui layout.
pub trait Panel {
    /// Render this panel into the given frame area.
    fn render(&self, frame: &mut Frame, area: Rect);

    /// Handle an input key event. Return true if handled.
    fn handle_input(&mut self, _key: crossterm::event::KeyEvent) -> bool {
        false
    }
}
