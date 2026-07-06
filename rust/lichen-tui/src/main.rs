//! lichen-tui — terminal dashboard for a LICHEN mesh node.
//!
//! Layout (Node tab):
//!   ┌─ Neighbors ──────────┬─ Node Info ────────────────────────┐
//!   │ ● fe80::1  -108 dBm  │ node      [::1]:5683               │
//!   │                      │ status    connected                 │
//!   │ ● fe80::2  -115 dBm  │ uptime    1h 23m                   │
//!   │                      │ firmware  0.1.0                     │
//!   ├──────────────────────┴───────────────────────────────────┤
//!   │ [Node] [Radio]  [::1]:5683  ↑↓/jk:nav  Tab:switch  q:quit│
//!   └──────────────────────────────────────────────────────────┘
//!
//! Layout (Radio tab):
//!   ┌─ Duty Cycle (1% / 1h rolling) ───────────────────────────┐
//!   │ ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  5.42%     │
//!   │ Budget: 34048 ms   Window: 60 min                         │
//!   │ Refill: Budget available                                  │
//!   ├─ TX Queue ───────────────────────────────────────────────┤
//!   │ Depth: 6   Bytes: 484   Drain: 32 ms                     │
//!   │ Control  1 █                                              │
//!   │ Routing  2 ██                                             │
//!   │ User     2 ██                                             │
//!   │ Bulk     1 █                                              │
//!   ├──────────────────────────────────────────────────────────┤
//!   │ [Node] [Radio]  Tab:switch  q:quit                       │
//!   └──────────────────────────────────────────────────────────┘
//!
//! Keys: ↑↓/jk — navigate neighbors  Tab — switch tab  q/Ctrl-C — quit

mod coap;
mod radio;
mod rf_health;

use ciborium::value::Value;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use radio::{render_radio_tab, RadioState};
use rf_health::{render_rf_health, RfHealthState};
use std::{io, net::SocketAddr, time::Duration};
use tokio::sync::watch;

/// LICHEN terminal user interface.
#[derive(Parser)]
#[command(name = "lichen-tui", version, about)]
struct Cli {
    /// CoAP endpoint address of the target node.
    #[arg(short, long, default_value = "[::1]:5683", env = "LICHEN_NODE")]
    node: SocketAddr,
}

// ── data types ────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct NodeStatus {
    uptime_secs: Option<u64>,
    firmware: Option<String>,
}

#[derive(Clone)]
struct Neighbor {
    addr: String,
    rssi: Option<i32>,
}

#[derive(Clone, Default)]
struct NodeData {
    status: NodeStatus,
    neighbors: Vec<Neighbor>,
}

// ── CBOR decoding ─────────────────────────────────────────────────────────────

fn parse_status(bytes: &[u8]) -> NodeStatus {
    let Ok(Value::Map(entries)) = ciborium::de::from_reader(bytes) else {
        return NodeStatus::default();
    };
    let mut s = NodeStatus::default();
    for (k, v) in entries {
        let Value::Text(key) = k else { continue };
        match key.as_str() {
            "uptime" => {
                if let Value::Integer(n) = v {
                    s.uptime_secs = Some(i128::from(n) as u64);
                }
            }
            "firmware" => {
                if let Value::Text(fw) = v {
                    s.firmware = Some(fw);
                }
            }
            _ => {}
        }
    }
    s
}

fn parse_neighbors(bytes: &[u8]) -> Vec<Neighbor> {
    let Ok(Value::Array(items)) = ciborium::de::from_reader(bytes) else {
        return vec![];
    };
    items
        .into_iter()
        .filter_map(|item| {
            let Value::Map(entries) = item else {
                return None;
            };
            let mut addr = None;
            let mut rssi = None;
            for (k, v) in entries {
                let Value::Text(key) = k else { continue };
                match key.as_str() {
                    "addr" => {
                        if let Value::Text(a) = v {
                            addr = Some(a);
                        }
                    }
                    "rssi" => {
                        if let Value::Integer(r) = v {
                            rssi = Some(i128::from(r) as i32);
                        }
                    }
                    _ => {}
                }
            }
            addr.map(|a| Neighbor { addr: a, rssi })
        })
        .collect()
}

// ── background polling ────────────────────────────────────────────────────────

async fn poll_node(node: SocketAddr) -> Result<NodeData, String> {
    let (sr, nr) = tokio::join!(coap::get(node, "status"), coap::get(node, "neighbors"));
    if let (Err(e), Err(_)) = (&sr, &nr) {
        return Err(e.clone());
    }
    Ok(NodeData {
        status: sr.ok().as_deref().map(parse_status).unwrap_or_default(),
        neighbors: nr.ok().as_deref().map(parse_neighbors).unwrap_or_default(),
    })
}

// ── app state ─────────────────────────────────────────────────────────────────

/// Active tab in the TUI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Node,
    Radio,
    RfHealth,
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Node => Tab::Radio,
            Tab::Radio => Tab::RfHealth,
            Tab::RfHealth => Tab::Node,
        }
    }
}

enum ConnState {
    Connecting,
    Connected,
    Error(String),
}

struct App {
    node: SocketAddr,
    data: NodeData,
    conn: ConnState,
    list_state: ListState,
    should_quit: bool,
    rx: watch::Receiver<Option<Result<NodeData, String>>>,
    /// Current active tab.
    tab: Tab,
    /// Radio statistics state.
    radio: RadioState,
    /// RF health and neighbor monitoring state.
    rf_health: RfHealthState,
}

impl App {
    fn new(node: SocketAddr, rx: watch::Receiver<Option<Result<NodeData, String>>>) -> Self {
        App {
            node,
            data: NodeData::default(),
            conn: ConnState::Connecting,
            list_state: ListState::default(),
            should_quit: false,
            rx,
            tab: Tab::default(),
            radio: RadioState::new(),
            rf_health: RfHealthState::demo(),
        }
    }

    fn apply_update(&mut self) {
        if !self.rx.has_changed().unwrap_or(false) {
            return;
        }
        let update = self.rx.borrow_and_update().clone();
        let Some(result) = update else { return };
        match result {
            Ok(data) => {
                let n = data.neighbors.len();
                if let Some(sel) = self.list_state.selected() {
                    if n == 0 {
                        self.list_state.select(None);
                    } else if sel >= n {
                        self.list_state.select(Some(n - 1));
                    }
                }
                self.data = data;
                self.conn = ConnState::Connected;
            }
            Err(e) => {
                self.conn = ConnState::Error(e);
            }
        }
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        match (code, mods) {
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            (KeyCode::Tab, _) => {
                self.tab = self.tab.next();
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) if self.tab == Tab::Node => {
                let n = self.data.neighbors.len();
                if n > 0 {
                    let i = self.list_state.selected().unwrap_or(0);
                    self.list_state.select(Some((i + 1).min(n - 1)));
                }
            }
            (KeyCode::Up, _) | (KeyCode::Char('k'), _)
                if self.tab == Tab::Node && !self.data.neighbors.is_empty() =>
            {
                let i = self.list_state.selected().unwrap_or(0);
                self.list_state.select(Some(i.saturating_sub(1)));
            }
            _ => {}
        }
    }
}

// ── drawing ───────────────────────────────────────────────────────────────────

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    match app.tab {
        Tab::Node => render_node_tab(f, app),
        Tab::Radio => render_radio_tab(f, f.area(), &mut app.radio),
        Tab::RfHealth => render_rf_health(f, f.area(), &app.rf_health),
    }
}

fn render_node_tab(f: &mut ratatui::Frame, app: &mut App) {
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(0)])
        .split(outer[0]);

    // ── Neighbors pane ────────────────────────────────────────────────────────
    let neighbor_items: Vec<ListItem> = if app.data.neighbors.is_empty() {
        let msg = match &app.conn {
            ConnState::Connecting => " Connecting...".into(),
            ConnState::Connected => " No neighbors".into(),
            ConnState::Error(e) => format!(" {e}"),
        };
        vec![ListItem::new(Span::styled(
            msg,
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.data
            .neighbors
            .iter()
            .map(|nb| {
                let rssi_str = nb
                    .rssi
                    .map(|r| format!("{r:+} dBm"))
                    .unwrap_or_else(|| "? dBm".into());
                ListItem::new(Line::from(vec![
                    Span::styled("* ", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!("{:<16}", truncate(&nb.addr, 16)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(rssi_str, Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect()
    };
    let neighbors = List::new(neighbor_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Neighbors ")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(neighbors, body[0], &mut app.list_state);

    // ── Node info pane ────────────────────────────────────────────────────────
    let conn_str = match &app.conn {
        ConnState::Connecting => Span::styled("connecting...", Style::default().fg(Color::Yellow)),
        ConnState::Connected => Span::styled("connected", Style::default().fg(Color::Green)),
        ConnState::Error(e) => Span::styled(truncate(e, 30), Style::default().fg(Color::Red)),
    };
    let uptime_str = app
        .data
        .status
        .uptime_secs
        .map(fmt_uptime)
        .unwrap_or_else(|| "-".into());
    let firmware_str = app
        .data
        .status
        .firmware
        .as_deref()
        .unwrap_or("-")
        .to_owned();

    let info_text = vec![
        Line::from(vec![
            Span::styled(
                format!("{:<10}", "node"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(app.node.to_string()),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<10}", "status"),
                Style::default().fg(Color::DarkGray),
            ),
            conn_str,
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<10}", "uptime"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(uptime_str),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<10}", "firmware"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(firmware_str),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<10}", "neighbors"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(app.data.neighbors.len().to_string()),
        ]),
    ];
    let info = Paragraph::new(info_text)
        .block(Block::default().borders(Borders::ALL).title(" Node Info "));
    f.render_widget(info, body[1]);

    // ── Status bar ────────────────────────────────────────────────────────────
    let tab_indicator = format!(
        " [{}Node{}] [{}Radio{}] [{}RF{}] ",
        if app.tab == Tab::Node { ">" } else { " " },
        if app.tab == Tab::Node { "<" } else { " " },
        if app.tab == Tab::Radio { ">" } else { " " },
        if app.tab == Tab::Radio { "<" } else { " " },
        if app.tab == Tab::RfHealth { ">" } else { " " },
        if app.tab == Tab::RfHealth { "<" } else { " " },
    );
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " LICHEN ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ),
        Span::styled(tab_indicator, Style::default().fg(Color::Cyan)),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(":switch  "),
        Span::styled("jk", Style::default().fg(Color::Yellow)),
        Span::raw(":nav  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit"),
    ]));
    f.render_widget(status, outer[1]);
}

fn fmt_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let node = cli.node;

    let (tx, rx) = watch::channel::<Option<Result<NodeData, String>>>(None);

    tokio::spawn(async move {
        loop {
            tx.send(Some(poll_node(node).await)).ok();
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let mut app = App::new(node, rx);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        app.apply_update();
        terminal.draw(|f| ui(f, app))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                app.on_key(key.code, key.modifiers);
            }
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}
