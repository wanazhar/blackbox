//! Daily-driver TUI — one screen for postmortem, processes, files, failures,
//! side effects, capture quality, handoff, and replay guarantees.

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
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use ratatui::Terminal;

use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::ui::panels::{
    anomaly_lines, build_header, coverage_lines, failure_story_lines, file_change_lines,
    help_lines, process_lines, replay_preflight_lines, side_effect_lines, timeline_lines,
    PanelLine, RunHeader,
};

/// Which pane has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Runs,
    Content,
}

/// Content panel mode (daily-driver workflow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentMode {
    Timeline,
    Processes,
    Files,
    Failures,
    Anomalies,
    SideEffects,
    CaptureQuality,
    Postmortem,
    Handoff,
    Replay,
    Diff,
    Help,
}

impl ContentMode {
    fn title(self) -> &'static str {
        match self {
            Self::Timeline => "Timeline",
            Self::Processes => "Processes",
            Self::Files => "Files",
            Self::Failures => "Failure story",
            Self::Anomalies => "Anomalies",
            Self::SideEffects => "Side effects",
            Self::CaptureQuality => "Capture quality",
            Self::Postmortem => "Postmortem",
            Self::Handoff => "Handoff",
            Self::Replay => "Replay preflight",
            Self::Diff => "Diff vs previous",
            Self::Help => "Help",
        }
    }

    fn key_hint(self) -> &'static str {
        match self {
            Self::Timeline => "t",
            Self::Processes => "o",
            Self::Files => "f",
            Self::Failures => "e",
            Self::Anomalies => "a",
            Self::SideEffects => "x",
            Self::CaptureQuality => "c",
            Self::Postmortem => "p",
            Self::Handoff => "h",
            Self::Replay => "r",
            Self::Diff => "d",
            Self::Help => "?",
        }
    }
}

/// The main TUI application.
struct App {
    focus: Focus,
    mode: ContentMode,
    runs: Vec<Run>,
    selected_run_idx: usize,
    events: Vec<TraceEvent>,
    content_lines: Vec<PanelLine>,
    content_idx: usize,
    scroll: u16,
    hide_bookkeeping: bool,
    /// Content filter substring (set via `/` then type — simple: toggle filter active empty clears).
    filter: String,
    header: RunHeader,
    status: String,
    postmortem_text: String,
    handoff_text: String,
    /// Cached trajectory diff text for `d` panel (selected vs previous run).
    diff_text: String,
    /// Cached summary for failure-story panel.
    last_summary: Option<crate::summary::SummaryView>,
    store: SqliteStore,
}

impl App {
    async fn load(store: SqliteStore, preferred_run_id: Option<&str>) -> anyhow::Result<Self> {
        let runs = store.list_runs().await?;
        let selected_run_idx = if let Some(pref) = preferred_run_id {
            if pref == "latest" {
                0
            } else {
                runs.iter()
                    .position(|r| r.id == pref || r.id.starts_with(pref))
                    .unwrap_or(0)
            }
        } else {
            0
        };

        let mut app = Self {
            focus: Focus::Runs,
            mode: ContentMode::Timeline,
            runs,
            selected_run_idx,
            events: Vec::new(),
            content_lines: Vec::new(),
            content_idx: 0,
            scroll: 0,
            hide_bookkeeping: true,
            filter: String::new(),
            header: RunHeader::default(),
            status: "Tab focus · ? help · / filter · q quit".into(),
            postmortem_text: String::new(),
            handoff_text: String::new(),
            diff_text: String::new(),
            last_summary: None,
            store,
        };
        app.reload_selected_run().await;
        Ok(app)
    }

    async fn reload_selected_run(&mut self) {
        let Some(run) = self.runs.get(self.selected_run_idx).cloned() else {
            self.events.clear();
            self.header = RunHeader::default();
            self.content_lines.clear();
            self.postmortem_text.clear();
            self.handoff_text.clear();
            self.diff_text.clear();
            self.last_summary = None;
            return;
        };

        match self.store.get_events(&run.id).await {
            Ok(events) => self.events = events,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load events");
                self.events = Vec::new();
                self.status = format!("error loading events: {e}");
            }
        }

        self.header = build_header(&run, &self.events);
        self.content_idx = 0;
        self.scroll = 0;

        // Build postmortem / handoff text from summary module.
        match crate::summary::build_summary(
            &self.store,
            &run,
            crate::summary::SummaryOptions::default(),
        )
        .await
        {
            Ok(summary) => {
                self.postmortem_text = crate::summary::format_summary_text(&summary);
                let mut handoff = String::new();
                handoff.push_str(&format!(
                    "Run: {} ({:?})\n",
                    summary.short_id, summary.status
                ));
                if !summary.headline.is_empty() {
                    handoff.push_str(&format!("Headline: {}\n", summary.headline));
                }
                if !summary.next_action.is_empty() {
                    handoff.push_str(&format!("Next: {}\n", summary.next_action));
                }
                if !summary.anomalies.is_empty() {
                    handoff.push_str(&format!("\nAnomalies: {}\n", summary.anomalies.len()));
                    for a in summary.anomalies.iter().take(5) {
                        handoff.push_str(&format!("  [{}|{}] {}\n", a.severity, a.kind, a.detail));
                    }
                }
                if !summary.narrative.is_empty() {
                    handoff.push_str("\nNarrative (truncated):\n");
                    for line in summary.narrative.lines().take(12) {
                        handoff.push_str(line);
                        handoff.push('\n');
                    }
                }
                if let Some(ref cmd) = summary.resume.command {
                    handoff.push_str(&format!("\nResume: {}\n", cmd.join(" ")));
                } else {
                    handoff.push_str("\nResume: (not available)\n");
                }
                handoff.push_str("\nCLI:\n");
                handoff.push_str("  blackbox handoff\n");
                handoff.push_str(&format!(
                    "  blackbox context {} --for-resume\n",
                    summary.short_id
                ));
                handoff.push_str(&format!("  blackbox postmortem {}\n", summary.short_id));
                if !summary.failure_fix_chains.is_empty() {
                    handoff.push_str(&format!(
                        "\nFailure-fix chains: {}\n",
                        summary.failure_fix_chains.len()
                    ));
                }
                self.handoff_text = handoff;
                self.last_summary = Some(summary);
            }
            Err(e) => {
                self.postmortem_text = format!("(postmortem unavailable: {e})");
                self.handoff_text = format!("(handoff unavailable: {e})");
                self.last_summary = None;
            }
        }

        self.refresh_diff_cache().await;
        self.rebuild_content_lines();
        self.status = format!(
            "loaded {} · {} events · mode={}",
            self.header.short_id,
            self.events.len(),
            self.header.mode
        );
    }

    /// Compare selected run (A) with the next-older run in the list (B = previous).
    async fn refresh_diff_cache(&mut self) {
        // list_runs is most-recent-first: previous chronologically is index+1.
        let prev_idx = self.selected_run_idx + 1;
        let (Some(run_a), Some(run_b)) = (
            self.runs.get(self.selected_run_idx).cloned(),
            self.runs.get(prev_idx).cloned(),
        ) else {
            self.diff_text =
                "(no previous run to compare — select a run that is not the oldest)".into();
            return;
        };
        let events_b = match self.store.get_events(&run_b.id).await {
            Ok(e) => e,
            Err(e) => {
                self.diff_text = format!("(failed to load previous run: {e})");
                return;
            }
        };
        let diff = crate::trajectory::diff_trajectories(
            &run_a.id,
            &self.events,
            &run_b.id,
            &events_b,
        );
        self.diff_text = crate::ui::panels::trajectory_diff_lines(&diff)
            .into_iter()
            .map(|l| l.text)
            .collect::<Vec<_>>()
            .join("\n");
    }

    fn rebuild_content_lines(&mut self) {
        self.content_lines = match self.mode {
            ContentMode::Timeline => timeline_lines(&self.events, self.hide_bookkeeping),
            ContentMode::Processes => process_lines(&self.events),
            ContentMode::Files => {
                let mut lines = file_change_lines(&self.events);
                if lines.is_empty() {
                    lines.push(PanelLine {
                        text: "(no filesystem changes observed)".into(),
                        event_id: None,
                    });
                }
                lines
            }
            ContentMode::Failures => {
                let run = self.runs.get(self.selected_run_idx);
                match run {
                    Some(r) => {
                        failure_story_lines(r, &self.events, self.last_summary.as_ref())
                    }
                    None => vec![PanelLine {
                        text: "(no run selected)".into(),
                        event_id: None,
                    }],
                }
            }
            ContentMode::Anomalies => anomaly_lines(&self.events),
            ContentMode::SideEffects => side_effect_lines(&self.events),
            ContentMode::CaptureQuality => coverage_lines(&self.events),
            ContentMode::Postmortem => self
                .postmortem_text
                .lines()
                .map(|l| PanelLine {
                    text: l.to_string(),
                    event_id: None,
                })
                .collect(),
            ContentMode::Handoff => self
                .handoff_text
                .lines()
                .map(|l| PanelLine {
                    text: l.to_string(),
                    event_id: None,
                })
                .collect(),
            ContentMode::Replay => replay_preflight_lines(&self.events),
            ContentMode::Diff => self
                .diff_text
                .lines()
                .map(|l| PanelLine {
                    text: l.to_string(),
                    event_id: None,
                })
                .collect(),
            ContentMode::Help => help_lines(),
        };
        if !self.filter.is_empty() {
            let f = self.filter.to_lowercase();
            self.content_lines
                .retain(|l| l.text.to_lowercase().contains(&f));
            if self.content_lines.is_empty() {
                self.content_lines.push(PanelLine {
                    text: format!("(no lines match filter {:?})", self.filter),
                    event_id: None,
                });
            }
        }
        if self.content_idx >= self.content_lines.len() {
            self.content_idx = self.content_lines.len().saturating_sub(1);
        }
    }

    fn set_mode(&mut self, mode: ContentMode) {
        self.mode = mode;
        self.focus = Focus::Content;
        self.content_idx = 0;
        self.scroll = 0;
        self.rebuild_content_lines();
        self.status = format!("{} panel ({})", mode.title(), mode.key_hint());
    }

    async fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Global keys (work regardless of focus).
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Char('?') => {
                self.set_mode(ContentMode::Help);
                return true;
            }
            KeyCode::Char('t') => {
                self.set_mode(ContentMode::Timeline);
                return true;
            }
            KeyCode::Char('o') => {
                self.set_mode(ContentMode::Processes);
                return true;
            }
            KeyCode::Char('f') => {
                self.set_mode(ContentMode::Files);
                return true;
            }
            KeyCode::Char('e') => {
                self.set_mode(ContentMode::Failures);
                return true;
            }
            KeyCode::Char('a') => {
                self.set_mode(ContentMode::Anomalies);
                return true;
            }
            KeyCode::Char('x') => {
                self.set_mode(ContentMode::SideEffects);
                return true;
            }
            KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.set_mode(ContentMode::CaptureQuality);
                return true;
            }
            KeyCode::Char('p') => {
                self.set_mode(ContentMode::Postmortem);
                return true;
            }
            KeyCode::Char('h') => {
                self.set_mode(ContentMode::Handoff);
                return true;
            }
            KeyCode::Char('r') => {
                self.set_mode(ContentMode::Replay);
                return true;
            }
            KeyCode::Char('d') => {
                self.refresh_diff_cache().await;
                self.set_mode(ContentMode::Diff);
                return true;
            }
            KeyCode::Char('/') => {
                // Cycle: clear filter + toggle bookkeeping; if filter empty start simple filter prompt state
                if !self.filter.is_empty() {
                    self.filter.clear();
                    self.rebuild_content_lines();
                    self.status = "filter cleared".into();
                } else if self.mode == ContentMode::Timeline {
                    self.hide_bookkeeping = !self.hide_bookkeeping;
                    self.rebuild_content_lines();
                    self.status = if self.hide_bookkeeping {
                        "timeline: bookkeeping hidden (type filter via F then Enter in status — use : prefix modes later)".into()
                    } else {
                        "timeline: showing all events".into()
                    };
                } else {
                    self.status = "filter: press f then letters… (cleared with /)".into();
                }
                return true;
            }
            KeyCode::Char('F') => {
                // Quick filter presets for failures / writes
                self.filter = if self.filter == "fail" {
                    "write".into()
                } else if self.filter == "write" {
                    String::new()
                } else {
                    "fail".into()
                };
                self.rebuild_content_lines();
                self.status = if self.filter.is_empty() {
                    "filter cleared".into()
                } else {
                    format!("filter={:?}", self.filter)
                };
                return true;
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Runs => Focus::Content,
                    Focus::Content => Focus::Runs,
                };
                return true;
            }
            _ => {}
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Home => {
                match self.focus {
                    Focus::Runs => self.selected_run_idx = 0,
                    Focus::Content => {
                        self.content_idx = 0;
                        self.scroll = 0;
                    }
                }
            }
            KeyCode::End => match self.focus {
                Focus::Runs if !self.runs.is_empty() => {
                    self.selected_run_idx = self.runs.len() - 1;
                }
                Focus::Content if !self.content_lines.is_empty() => {
                    self.content_idx = self.content_lines.len() - 1;
                }
                _ => {}
            },
            KeyCode::Enter => match self.focus {
                Focus::Runs => {
                    self.reload_selected_run().await;
                    self.focus = Focus::Content;
                }
                Focus::Content => {
                    if let Some(line) = self.content_lines.get(self.content_idx) {
                        if let Some(ref id) = line.event_id {
                            // Inline inspect: pull event from loaded list
                            if let Some(ev) = self.events.iter().find(|e| e.id == *id || e.id.starts_with(id)) {
                                let meta = serde_json::to_string(&ev.metadata).unwrap_or_default();
                                let meta = if meta.len() > 200 {
                                    format!("{}…", &meta[..meta.floor_char_boundary(200)])
                                } else {
                                    meta
                                };
                                self.status = format!(
                                    "inspect {} seq={} {:?} blob={} meta={}",
                                    &ev.id[..8.min(ev.id.len())],
                                    ev.sequence,
                                    ev.status,
                                    ev.output_blob.as_deref().unwrap_or("—"),
                                    meta
                                );
                            } else {
                                self.status = format!(
                                    "event {} — blackbox show/timeline for full payload",
                                    &id[..8.min(id.len())]
                                );
                            }
                        } else {
                            self.status = line.text.chars().take(120).collect();
                        }
                    }
                }
            },
            _ => {}
        }
        true
    }

    fn move_selection(&mut self, delta: i32) {
        match self.focus {
            Focus::Runs => {
                if self.runs.is_empty() {
                    return;
                }
                let new = (self.selected_run_idx as i32 + delta).max(0) as usize;
                self.selected_run_idx = new.min(self.runs.len() - 1);
            }
            Focus::Content => {
                if self.content_lines.is_empty() {
                    return;
                }
                let new = (self.content_idx as i32 + delta).max(0) as usize;
                self.content_idx = new.min(self.content_lines.len() - 1);
                // Keep selection roughly in view.
                if self.content_idx < self.scroll as usize {
                    self.scroll = self.content_idx as u16;
                }
            }
        }
    }
}

fn render_layout(frame: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header
            Constraint::Min(5),    // body
            Constraint::Length(1), // status
            Constraint::Length(1), // keymap
        ])
        .split(frame.area());

    render_header(frame, root[0], app);
    render_body(frame, root[1], app);
    render_status(frame, root[2], app);
    render_keymap(frame, root[3], app);
}

fn render_header(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let h = &app.header;
    let line1 = Line::from(vec![
        Span::styled(
            format!("{} ", h.name),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("[{}]  ", h.short_id)),
        Span::styled(
            format!("{}  ", h.status),
            match h.status.as_str() {
                "Succeeded" => Style::default().fg(Color::Green),
                "Failed" | "Cancelled" => Style::default().fg(Color::Red),
                "Running" => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            },
        ),
        Span::raw(format!(
            "adapter={}  dur={}  mode={}",
            h.adapter, h.duration, h.mode
        )),
    ]);
    let line2 = Line::from(vec![
        Span::raw(format!(
            "capture={}  files={}  failures={}  side-effects={}",
            h.capture_quality, h.files_changed, h.failure_count, h.side_effect_risk
        )),
    ]);
    let para = Paragraph::new(vec![line1, line2]).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Blackbox · daily driver"),
    );
    frame.render_widget(para, area);
}

fn render_body(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(area);

    // Runs list
    let runs_border = if app.focus == Focus::Runs {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let runs_items: Vec<Line> = app
        .runs
        .iter()
        .enumerate()
        .map(|(i, run)| {
            let name = run.name.as_deref().unwrap_or("(unnamed)");
            let status = match &run.status {
                crate::core::run::RunStatus::Succeeded => "✓",
                crate::core::run::RunStatus::Failed => "✗",
                crate::core::run::RunStatus::Running => "●",
                _ => "?",
            };
            let style = if i == app.selected_run_idx {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(Span::styled(
                format!(
                    "{} {}  {}",
                    status,
                    run.id.get(..8).unwrap_or(&run.id),
                    name
                ),
                style,
            ))
        })
        .collect();
    let runs_para = Paragraph::new(runs_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Runs")
                .border_style(runs_border),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(runs_para, cols[0]);

    // Content panel
    let content_border = if app.focus == Focus::Content {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };
    let title = format!(
        "{}  [{}]  ({}/{})",
        app.mode.title(),
        app.mode.key_hint(),
        if app.content_lines.is_empty() {
            0
        } else {
            app.content_idx + 1
        },
        app.content_lines.len()
    );
    let visible: Vec<Line> = app
        .content_lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let style = if i == app.content_idx && app.focus == Focus::Content {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(Span::styled(line.text.clone(), style))
        })
        .collect();
    let content_para = Paragraph::new(visible)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(content_border),
        )
        .scroll((app.scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(content_para, cols[1]);
}

fn render_status(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let para = Paragraph::new(Span::styled(
        app.status.chars().take(area.width as usize).collect::<String>(),
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(para, area);
}

fn render_keymap(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let focus = match app.focus {
        Focus::Runs => "runs",
        Focus::Content => "content",
    };
    let text = format!(
        " focus={focus} │ t timeline  o proc  f files  e fail  x side  c cover  p post  h handoff  r replay  d diff  / filter  ? help  q quit"
    );
    let para = Paragraph::new(Span::styled(
        text.chars().take(area.width as usize).collect::<String>(),
        Style::default().bg(Color::DarkGray).fg(Color::White),
    ));
    frame.render_widget(para, area);
}

/// Run the TUI event loop, opening the default store path.
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
