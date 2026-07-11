//! RF health and neighbor monitoring tab for LICHEN TUI.
//!
//! Displays:
//! - Packet statistics (TX/RX/dropped/failures)
//! - RSSI/SNR statistics (min/max/avg)
//! - Packet loss rate
//! - Neighbor table with duty cycle status
//! - Flagged cheaters list

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame,
};

// ── data types ────────────────────────────────────────────────────────────────

/// RF health metrics for display (mirrors lichen_core::rf_health::RfHealthMetrics).
#[derive(Clone, Debug, Default)]
pub struct RfHealthDisplay {
    /// Total packets transmitted.
    pub packets_tx: u32,
    /// Total packets received.
    pub packets_rx: u32,
    /// Packets dropped (buffer full, parse error, etc.).
    pub packets_dropped: u32,
    /// TX failures (no ack, channel busy, etc.).
    pub tx_failures: u32,
    /// RSSI statistics.
    pub rssi: RssiDisplay,
    /// SNR statistics.
    pub snr: SnrDisplay,
    /// Packet loss rate as percentage (0-100).
    pub loss_percent: u8,
    /// Packet loss rate as permille for finer granularity (0-1000).
    pub loss_permille: u16,
}

/// RSSI statistics for display.
#[derive(Clone, Debug, Default)]
pub struct RssiDisplay {
    /// Minimum RSSI observed (dBm), None if no samples.
    pub min: Option<i16>,
    /// Maximum RSSI observed (dBm), None if no samples.
    pub max: Option<i16>,
    /// Rolling average RSSI (dBm), None if no samples.
    pub avg: Option<i16>,
    /// Number of samples recorded.
    #[allow(dead_code)] // populated but not yet rendered
    pub count: u32,
}

/// SNR statistics for display.
#[derive(Clone, Debug, Default)]
pub struct SnrDisplay {
    /// Minimum SNR observed (dB), None if no samples.
    pub min: Option<i8>,
    /// Maximum SNR observed (dB), None if no samples.
    pub max: Option<i8>,
    /// Rolling average SNR (dB), None if no samples.
    pub avg: Option<i8>,
    /// Number of samples recorded.
    #[allow(dead_code)] // populated but not yet rendered
    pub count: u32,
}

/// A neighbor entry for display.
#[derive(Clone, Debug)]
pub struct NeighborEntry {
    /// Node identifier (hex string).
    pub node_id: String,
    /// Packet count observed in the current window.
    pub packet_count: usize,
    /// Whether this neighbor is flagged as a cheater.
    pub is_cheater: bool,
    /// Last RSSI observed (if available).
    pub last_rssi: Option<i16>,
}

/// State for the RF health tab.
#[derive(Clone, Debug, Default)]
pub struct RfHealthState {
    /// RF health metrics.
    pub metrics: RfHealthDisplay,
    /// Neighbor table entries.
    pub neighbors: Vec<NeighborEntry>,
    /// List of flagged cheater node IDs.
    pub cheaters: Vec<String>,
}

impl RfHealthState {
    /// Create a new RF health state with demo data for testing.
    #[cfg(debug_assertions)]
    pub fn demo() -> Self {
        Self {
            metrics: RfHealthDisplay {
                packets_tx: 1234,
                packets_rx: 5678,
                packets_dropped: 12,
                tx_failures: 3,
                rssi: RssiDisplay {
                    min: Some(-115),
                    max: Some(-72),
                    avg: Some(-89),
                    count: 5678,
                },
                snr: SnrDisplay {
                    min: Some(-5),
                    max: Some(12),
                    avg: Some(6),
                    count: 5678,
                },
                loss_percent: 0,
                loss_permille: 2, // 0.2%
            },
            neighbors: vec![
                NeighborEntry {
                    node_id: "0102030405060708".into(),
                    packet_count: 15,
                    is_cheater: false,
                    last_rssi: Some(-85),
                },
                NeighborEntry {
                    node_id: "aabbccddeeff0011".into(),
                    packet_count: 42,
                    is_cheater: true,
                    last_rssi: Some(-72),
                },
                NeighborEntry {
                    node_id: "1122334455667788".into(),
                    packet_count: 8,
                    is_cheater: false,
                    last_rssi: Some(-98),
                },
            ],
            cheaters: vec!["aabbccddeeff0011".into()],
        }
    }

    /// Create an empty RF health state.
    #[cfg(not(debug_assertions))]
    pub fn demo() -> Self {
        Self::default()
    }
}

// ── rendering ─────────────────────────────────────────────────────────────────

/// Render the RF health tab.
pub fn render_rf_health(f: &mut Frame, area: Rect, state: &RfHealthState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Metrics section
            Constraint::Min(0),    // Neighbors and cheaters
            Constraint::Length(1), // Status bar
        ])
        .split(area);

    render_metrics(f, chunks[0], &state.metrics);
    render_neighbors_and_cheaters(f, chunks[1], state);
    render_status_bar(f, chunks[2]);
}

/// Render the metrics section (packet stats + signal quality).
fn render_metrics(f: &mut Frame, area: Rect, metrics: &RfHealthDisplay) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: Packet statistics
    let packet_stats = vec![
        Line::from(vec![
            Span::styled(
                format!("{:<12}", "TX:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{}", metrics.packets_tx),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<12}", "RX:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{}", metrics.packets_rx),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<12}", "Dropped:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{}", metrics.packets_dropped),
                Style::default().fg(if metrics.packets_dropped > 0 {
                    Color::Yellow
                } else {
                    Color::Green
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<12}", "TX Fail:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("{}", metrics.tx_failures),
                Style::default().fg(if metrics.tx_failures > 0 {
                    Color::Red
                } else {
                    Color::Green
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<12}", "Loss:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_loss_rate(metrics.loss_percent, metrics.loss_permille),
                Style::default().fg(loss_color(metrics.loss_percent)),
            ),
        ]),
    ];

    let packet_widget = Paragraph::new(packet_stats).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Packets ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(packet_widget, chunks[0]);

    // Right: Signal quality (RSSI/SNR)
    let signal_stats = vec![
        Line::from(vec![
            Span::styled(
                "RSSI",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" (dBm)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<6}", "min:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_opt_i16(metrics.rssi.min),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("  {:<6}", "max:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_opt_i16(metrics.rssi.max),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("  {:<6}", "avg:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_opt_i16(metrics.rssi.avg),
                Style::default().fg(rssi_color(metrics.rssi.avg)),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "SNR",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" (dB)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:<6}", "min:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_opt_i8(metrics.snr.min),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("  {:<6}", "max:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_opt_i8(metrics.snr.max),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("  {:<6}", "avg:"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format_opt_i8(metrics.snr.avg),
                Style::default().fg(snr_color(metrics.snr.avg)),
            ),
        ]),
    ];

    let signal_widget = Paragraph::new(signal_stats).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Signal Quality ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(signal_widget, chunks[1]);
}

/// Render neighbors table and cheaters list.
fn render_neighbors_and_cheaters(f: &mut Frame, area: Rect, state: &RfHealthState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    // Left: Neighbor table
    let header = Row::new(vec!["Node ID", "Pkts", "RSSI", "Status"])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let rows: Vec<Row> = state
        .neighbors
        .iter()
        .map(|n| {
            let (status, style) = if n.is_cheater {
                (
                    "CHEATER",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else {
                ("OK", Style::default().fg(Color::Green))
            };

            Row::new(vec![
                truncate_node_id(&n.node_id),
                format!("{}", n.packet_count),
                n.last_rssi
                    .map(|r| format!("{}", r))
                    .unwrap_or_else(|| "-".into()),
                status.into(),
            ])
            .style(style)
            .height(1)
        })
        .collect();

    let widths = [
        Constraint::Length(18),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Neighbors ({}) ", state.neighbors.len()))
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, chunks[0]);

    // Right: Cheaters list
    let cheater_items: Vec<ListItem> = if state.cheaters.is_empty() {
        vec![ListItem::new(Span::styled(
            " None detected",
            Style::default().fg(Color::Green),
        ))]
    } else {
        state
            .cheaters
            .iter()
            .map(|id| {
                ListItem::new(Line::from(vec![
                    Span::styled("! ", Style::default().fg(Color::Red)),
                    Span::styled(
                        truncate_node_id(id),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ]))
            })
            .collect()
    };

    let cheaters_widget = List::new(cheater_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Cheaters ({}) ", state.cheaters.len()))
            .border_style(Style::default().fg(Color::Red)),
    );
    f.render_widget(cheaters_widget, chunks[1]);
}

/// Render the status bar.
fn render_status_bar(f: &mut Frame, area: Rect) {
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" RF ", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw("  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(":reset  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(":switch  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit"),
    ]));
    f.render_widget(status, area);
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Format optional i16 value for display.
fn format_opt_i16(val: Option<i16>) -> String {
    val.map(|v| format!("{:+}", v))
        .unwrap_or_else(|| "-".into())
}

/// Format optional i8 value for display.
fn format_opt_i8(val: Option<i8>) -> String {
    val.map(|v| format!("{:+}", v))
        .unwrap_or_else(|| "-".into())
}

/// Format loss rate for display, using permille for fractional percentages.
fn format_loss_rate(percent: u8, permille: u16) -> String {
    if percent > 0 {
        format!("{}%", percent)
    } else if permille > 0 {
        format!("{}.{}%", permille / 10, permille % 10)
    } else {
        "0%".into()
    }
}

/// Get color for RSSI value.
fn rssi_color(rssi: Option<i16>) -> Color {
    match rssi {
        Some(r) if r >= -70 => Color::Green,
        Some(r) if r >= -85 => Color::Yellow,
        Some(r) if r >= -100 => Color::LightRed,
        Some(_) => Color::Red,
        None => Color::DarkGray,
    }
}

/// Get color for SNR value.
fn snr_color(snr: Option<i8>) -> Color {
    match snr {
        Some(s) if s >= 10 => Color::Green,
        Some(s) if s >= 5 => Color::Yellow,
        Some(s) if s >= 0 => Color::LightRed,
        Some(_) => Color::Red,
        None => Color::DarkGray,
    }
}

/// Get color for loss rate.
fn loss_color(percent: u8) -> Color {
    match percent {
        0 => Color::Green,
        1..=5 => Color::Yellow,
        6..=15 => Color::LightRed,
        _ => Color::Red,
    }
}

/// Truncate node ID for display (show first 8 + last 4 hex chars with ...).
fn truncate_node_id(id: &str) -> String {
    if id.len() <= 14 {
        id.to_owned()
    } else {
        format!("{}..{}", &id[..8], &id[id.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_loss_rate() {
        assert_eq!(format_loss_rate(10, 100), "10%");
        assert_eq!(format_loss_rate(0, 5), "0.5%");
        assert_eq!(format_loss_rate(0, 0), "0%");
    }

    #[test]
    fn test_rssi_color() {
        assert_eq!(rssi_color(Some(-60)), Color::Green);
        assert_eq!(rssi_color(Some(-80)), Color::Yellow);
        assert_eq!(rssi_color(Some(-95)), Color::LightRed);
        assert_eq!(rssi_color(Some(-110)), Color::Red);
        assert_eq!(rssi_color(None), Color::DarkGray);
    }

    #[test]
    fn test_snr_color() {
        assert_eq!(snr_color(Some(15)), Color::Green);
        assert_eq!(snr_color(Some(7)), Color::Yellow);
        assert_eq!(snr_color(Some(2)), Color::LightRed);
        assert_eq!(snr_color(Some(-5)), Color::Red);
        assert_eq!(snr_color(None), Color::DarkGray);
    }

    #[test]
    fn test_truncate_node_id() {
        assert_eq!(truncate_node_id("short"), "short");
        assert_eq!(truncate_node_id("0102030405060708"), "01020304..0708");
    }

    #[test]
    fn test_format_opt_i16() {
        assert_eq!(format_opt_i16(Some(-80)), "-80");
        assert_eq!(format_opt_i16(Some(5)), "+5");
        assert_eq!(format_opt_i16(None), "-");
    }

    #[test]
    fn test_format_opt_i8() {
        assert_eq!(format_opt_i8(Some(-5)), "-5");
        assert_eq!(format_opt_i8(Some(10)), "+10");
        assert_eq!(format_opt_i8(None), "-");
    }
}
