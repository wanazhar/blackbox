use std::io;
use std::time::Duration;

use anyhow::Context;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use ratatui::Terminal;

use crate::core::event::TraceEvent;
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::ui::event::EventView;
use crate::ui::runs::RunsView;
use crate::ui::timeline_v::TimelineView;

/// Which panel currently has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Runs,
    Timeline,
    EventDetail,
}

/// The main TUI application.
pub struct App {
    focus: Focus,
    runs: RunsView,
    _timeline: TimelineView,
    _event_detail: EventView,
    events: Vec<TraceEvent>,
    selected_run_idx: usize,
    selected_event_idx: usize,
    run_ids: Vec<String>,
    store: SqliteStore,
}

impl App {
    async fn load(store: SqliteStore, preferred_run_id: Option<&str>) -> anyhow::Result<Self> {
        let runs = store.list_runs().await?;
        let run_ids: Vec<String> = runs.iter().map(|r| r.id.clone()).collect();

        // Resolve preferred run: exact id, prefix match, "latest", or first
        let selected_run_idx = if let Some(pref) = preferred_run_id {
            if pref == "latest" {
                0 // list_runs is most-recent-first
            } else {
                run_ids
                    .iter()
                    .position(|id| id == pref || id.starts_with(pref))
                    .unwrap_or(0)
            }
        } else {
            0
        };

        // Load events for the selected run (if any)
        let events = if let Some(run_id) = run_ids.get(selected_run_idx) {
            store.get_events(run_id).await?
        } else {
            Vec::new()
        };

        let mut event_detail = EventView::new();
        if let Some(ev) = events.first() {
            event_detail.set_event(ev.clone());
        }

        Ok(Self {
            focus: Focus::Runs,
            runs: RunsView::new(runs),
            _timeline: TimelineView::new(events.clone()),
            _event_detail: event_detail,
            events,
            selected_run_idx,
            selected_event_idx: 0,
            run_ids,
            store,
        })
    }

    async fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Esc => return false,

            // Tab to cycle focus
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Runs => Focus::Timeline,
                    Focus::Timeline => Focus::EventDetail,
                    Focus::EventDetail => Focus::Runs,
                };
            }

            // Navigation within panels
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),

            // Enter to select from runs list
            KeyCode::Enter if self.focus == Focus::Runs => {
                self.select_run().await;
            }

            // Enter to select event from timeline
            KeyCode::Enter if self.focus == Focus::Timeline => {
                self.select_event();
            }

            // Home/End
            KeyCode::Home => self.move_to_top(),
            KeyCode::End => self.move_to_bottom(),

            _ => {}
        }
        true
    }

    fn move_selection(&mut self, delta: i32) {
        match self.focus {
            Focus::Runs => {
                let max = self.run_ids.len();
                if max == 0 {
                    return;
                }
                let new = (self.selected_run_idx as i32 + delta).max(0) as usize;
                self.selected_run_idx = new.min(max - 1);
            }
            Focus::Timeline => {
                let max = self.events.len();
                if max == 0 {
                    return;
                }
                let new = (self.selected_event_idx as i32 + delta).max(0) as usize;
                self.selected_event_idx = new.min(max - 1);
            }
            Focus::EventDetail => {}
        }
    }

    fn move_to_top(&mut self) {
        match self.focus {
            Focus::Runs if !self.run_ids.is_empty() => {
                self.selected_run_idx = 0;
            }
            Focus::Timeline if !self.events.is_empty() => {
                self.selected_event_idx = 0;
            }
            _ => {}
        }
    }

    fn move_to_bottom(&mut self) {
        match self.focus {
            Focus::Runs if !self.run_ids.is_empty() => {
                self.selected_run_idx = self.run_ids.len() - 1;
            }
            Focus::Timeline if !self.events.is_empty() => {
                self.selected_event_idx = self.events.len() - 1;
            }
            _ => {}
        }
    }

    async fn select_run(&mut self) {
        if let Some(run_id) = self.run_ids.get(self.selected_run_idx) {
            let run_id = run_id.clone();
            match self.store.get_events(&run_id).await {
                Ok(events) => {
                    self.events = events;
                    self.selected_event_idx = 0;
                    self._timeline = TimelineView::new(self.events.clone());
                    self._event_detail = EventView::new();
                }
                Err(e) => {
                    // M-30: Log DB error so silent failures are diagnosable.
                    tracing::warn!(run_id = %run_id, error = %e, "failed to load events for run");
                    self.events = Vec::new();
                    self.selected_event_idx = 0;
                    self._timeline = TimelineView::new(Vec::new());
                    self._event_detail = EventView::new();
                }
            }
        }
    }

    fn select_event(&mut self) {
        if let Some(ev) = self.events.get(self.selected_event_idx) {
            self._event_detail.set_event(ev.clone());
        }
    }
}

fn render_layout(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50), // Runs + Timeline
            Constraint::Percentage(50), // Event detail
        ])
        .split(frame.area());

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Runs list
            Constraint::Percentage(60), // Timeline
        ])
        .split(chunks[0]);

    // Runs panel (highlighted if focused)
    let runs_style = if app.focus == Focus::Runs {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let runs_block = Block::default()
        .borders(Borders::ALL)
        .title("Runs")
        .style(runs_style);
    // Render runs content
    let runs_items: Vec<Line> = app
        .runs
        .runs
        .iter()
        .enumerate()
        .map(|(i, run)| {
            let name = run.name.as_deref().unwrap_or("(unnamed)");
            let status = match &run.status {
                crate::core::run::RunStatus::Succeeded => "\u{2713}",
                crate::core::run::RunStatus::Failed => "\u{2717}",
                crate::core::run::RunStatus::Running => "\u{25CF}",
                _ => "?",
            };
            let style = if i == app.selected_run_idx && app.focus == Focus::Runs {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(Span::styled(
                format!("{} {}  {}", status, run.id.get(..8).unwrap_or(&run.id), name),
                style,
            ))
        })
        .collect();
    let runs_para = Paragraph::new(runs_items).block(runs_block);
    frame.render_widget(runs_para, top_chunks[0]);

    // Timeline panel
    let timeline_style = if app.focus == Focus::Timeline {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let timeline_block = Block::default()
        .borders(Borders::ALL)
        .title("Timeline")
        .style(timeline_style);
    let timeline_items: Vec<Line> = app
        .events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let offset = ev.started_at.format("%H:%M:%S").to_string();
            let style = if i == app.selected_event_idx && app.focus == Focus::Timeline {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(
                    format!("{}  {}  {:?}", offset, ev.kind, ev.status),
                    style,
                ),
            ])
        })
        .collect();
    let timeline_para = Paragraph::new(timeline_items).block(timeline_block);
    frame.render_widget(timeline_para, top_chunks[1]);

    // Event detail panel
    let detail_style = if app.focus == Focus::EventDetail {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .title("Event Details")
        .style(detail_style);
    let detail_text = match app.events.get(app.selected_event_idx) {
        Some(ev) => {
            let preview = ev
                .metadata
                .get("preview")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    ev.metadata
                        .get("tool_name")
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("");
            // M-29: Truncate long metadata previews to avoid rendering huge text blocks.
            const MAX_PREVIEW: usize = 200;
            let preview = if preview.len() > MAX_PREVIEW {
                let mut end = MAX_PREVIEW;
                while !preview.is_char_boundary(end) {
                    end -= 1;
                }
                &preview[..end]
            } else {
                preview
            };
            let blob = ev.output_blob.as_deref().unwrap_or("—");
            format!(
                "ID:     {}\nKind:   {}\nSource: {:?}\nStatus: {:?}\nStart:  {}\nBlob:   {}\n\n{}",
                ev.id,
                ev.kind,
                ev.source,
                ev.status,
                ev.started_at.format("%H:%M:%S.%3f"),
                blob,
                preview,
            )
        }
        None => "Select an event to inspect".to_string(),
    };
    let detail_para = Paragraph::new(detail_text).block(detail_block);
    frame.render_widget(detail_para, chunks[1]);
}

/// Run the TUI event loop, opening the default store path.
///
/// `run_id` may be a full UUID, a prefix, `"latest"`, or `None`.
pub async fn run_tui(run_id: Option<&str>) -> anyhow::Result<()> {
    let paths = crate::config::BlackboxPaths::resolve(None, None)?;
    paths.ensure_dirs()?;
    let store = SqliteStore::open_with_blobs(&paths.db_path, &paths.blob_dir)
        .context("failed to open database")?;
    run_tui_with_store(store, run_id).await
}

/// Run the TUI with an already-opened store.
pub async fn run_tui_with_store(store: SqliteStore, run_id: Option<&str>) -> anyhow::Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    let mut app = App::load(store, run_id).await?;

    let tick_rate = Duration::from_millis(100);
    let result = async {
        loop {
            terminal.draw(|frame| render_layout(frame, &app))?;

            if event::poll(tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break;
                    }
                    if !app.handle_key(key).await {
                        break;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    // M-31: Always restore terminal state; log errors for diagnostics.
    if let Err(e) = disable_raw_mode() {
        tracing::warn!(error = %e, "failed to disable raw mode during cleanup");
    }
    if let Err(e) = execute!(terminal.backend_mut(), LeaveAlternateScreen) {
        tracing::warn!(error = %e, "failed to leave alternate screen during cleanup");
    }
    if let Err(e) = terminal.show_cursor() {
        tracing::warn!(error = %e, "failed to restore cursor during cleanup");
    }

    result
}
