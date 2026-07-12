//! Radio statistics tab: duty cycle usage and TX queue status.
//!
//! Displays:
//!   - Duty cycle usage bar (visual, percentage, ms remaining)
//!   - Time until budget refill
//!   - TX queue depth by priority (Control/Routing/User/Bulk)
//!   - Estimated drain time

use lichen_core::duty_cycle::{DutyCycleTracker, WINDOW_MS};
use lichen_core::tx_queue::{
    TxPriority, TxQueue, DEADLINE_BULK_MS, DEADLINE_CONTROL_MS, DEADLINE_ROUTING_MS,
    DEADLINE_USER_MS,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

/// Radio statistics state for the dashboard tab.
pub struct RadioState {
    /// Duty cycle tracker (simulated).
    pub duty_cycle: DutyCycleTracker<64>,
    /// TX queue (simulated).
    pub tx_queue: TxQueue,
    /// Current timestamp in milliseconds (simulated time).
    pub now_ms: u64,
    /// Airtime per byte in microseconds (for drain time estimation).
    /// SF10/125kHz is roughly 8.2 us/bit = 65.6 us/byte.
    pub airtime_per_byte_us: u32,
}

impl Default for RadioState {
    fn default() -> Self {
        Self::new()
    }
}

impl RadioState {
    /// Create a new radio state with empty trackers.
    pub fn new() -> Self {
        let mut state = Self {
            duty_cycle: DutyCycleTracker::new(),
            tx_queue: TxQueue::new(),
            now_ms: 0,
            airtime_per_byte_us: 66, // ~SF10/125kHz
        };

        #[cfg(debug_assertions)]
        {
            // Seed with demo data for development
            state.seed_demo_data();
        }

        state
    }

    /// Seed demo data for development/testing.
    #[cfg(debug_assertions)]
    fn seed_demo_data(&mut self) {
        // Simulate some recent transmissions
        // Start time: 1 hour into operation
        self.now_ms = 3_700_000;

        // Record some past transmissions (spread over the last hour)
        self.duty_cycle.record_tx(100_000, 250);
        self.duty_cycle.record_tx(300_000, 180);
        self.duty_cycle.record_tx(600_000, 320);
        self.duty_cycle.record_tx(1_200_000, 150);
        self.duty_cycle.record_tx(1_800_000, 280);
        self.duty_cycle.record_tx(2_400_000, 200);
        self.duty_cycle.record_tx(3_000_000, 350);
        self.duty_cycle.record_tx(3_600_000, 220);

        // Add some items to the TX queue (capacity is 4 per spec)
        let now = self.now_ms;
        let _ = self.tx_queue.push(
            TxPriority::Control,
            now + DEADLINE_CONTROL_MS,
            now,
            &[0u8; 12],
        ); // ACK
        let _ = self.tx_queue.push(
            TxPriority::Routing,
            now + DEADLINE_ROUTING_MS,
            now,
            &[0u8; 48],
        ); // RPL DIO
        let _ = self.tx_queue.push(TxPriority::User, now + DEADLINE_USER_MS, now, &[0u8; 64]); // User message
        let _ = self.tx_queue.push(TxPriority::Bulk, now + DEADLINE_BULK_MS, now, &[0u8; 200]); // Firmware chunk
    }

    /// Advance simulated time (call from main event loop).
    pub fn tick(&mut self, delta_ms: u64) {
        self.now_ms = self.now_ms.wrapping_add(delta_ms);
    }

    /// Get duty cycle usage as a fraction (0.0 to 1.0+).
    pub fn duty_cycle_fraction(&mut self) -> f64 {
        self.duty_cycle.usage_permille(self.now_ms) as f64 / 1000.0
    }

    /// Get remaining TX budget in milliseconds.
    pub fn remaining_budget_ms(&mut self) -> u32 {
        self.duty_cycle.remaining_ms(self.now_ms)
    }

    /// Get time until next budget refill (oldest TX ages out).
    pub fn time_until_refill_ms(&mut self) -> Option<u64> {
        // The tracker doesn't expose this directly, so we estimate:
        // Budget refills as old TXes age out of the 1-hour window.
        // We'll check when a 1ms TX would be allowed if we're near limit.
        let next = self.duty_cycle.next_tx_available_ms(self.now_ms, 1);
        if next == self.now_ms {
            None // Budget available now
        } else if next == u64::MAX {
            Some(u64::MAX) // Never (shouldn't happen for 1ms)
        } else {
            Some(next.saturating_sub(self.now_ms))
        }
    }
}

/// Render the radio statistics tab.
pub fn render_radio_tab(f: &mut Frame, area: Rect, state: &mut RadioState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Duty cycle section
            Constraint::Length(1), // Spacer
            Constraint::Length(9), // TX queue section
            Constraint::Min(0),    // Remaining space
            Constraint::Length(1), // Status bar
        ])
        .split(area);

    // ── Duty Cycle Section ──
    render_duty_cycle(f, chunks[0], state);

    // ── TX Queue Section ──
    render_tx_queue(f, chunks[2], state);

    // ── Status bar ──
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" RADIO ", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw("  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(":switch  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit"),
    ]));
    f.render_widget(status, chunks[4]);
}

fn render_duty_cycle(f: &mut Frame, area: Rect, state: &mut RadioState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Duty Cycle (1% / 1h rolling) ")
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Usage gauge
            Constraint::Length(1), // Stats line
            Constraint::Length(1), // Refill info
            Constraint::Min(0),    // Padding
        ])
        .split(inner);

    // Usage gauge
    let usage_frac = state.duty_cycle_fraction();
    let usage_pct = (usage_frac * 100.0).min(100.0);
    let gauge_color = if usage_frac >= 0.9 {
        Color::Red
    } else if usage_frac >= 0.7 {
        Color::Yellow
    } else {
        Color::Green
    };

    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(gauge_color).bg(Color::DarkGray))
        .percent(usage_pct as u16)
        .label(format!("{:.2}%", usage_frac * 100.0));
    f.render_widget(gauge, inner_chunks[0]);

    // Stats line
    let remaining = state.remaining_budget_ms();
    let stats_line = Line::from(vec![
        Span::styled("Budget: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} ms", remaining),
            Style::default().fg(if remaining > 10000 { Color::Green } else { Color::Yellow }),
        ),
        Span::raw("  "),
        Span::styled("Window: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{} min", WINDOW_MS / 60_000)),
    ]);
    f.render_widget(Paragraph::new(stats_line), inner_chunks[1]);

    // Refill info
    let refill_str = match state.time_until_refill_ms() {
        None => "Budget available".to_string(),
        Some(ms) if ms == u64::MAX => "Budget exhausted".to_string(),
        Some(ms) => format_duration_ms(ms),
    };
    let refill_line = Line::from(vec![
        Span::styled("Refill: ", Style::default().fg(Color::DarkGray)),
        Span::raw(refill_str),
    ]);
    f.render_widget(Paragraph::new(refill_line), inner_chunks[2]);
}

fn render_tx_queue(f: &mut Frame, area: Rect, state: &mut RadioState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" TX Queue ")
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let stats = state.tx_queue.stats();

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Summary
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Control
            Constraint::Length(1), // Routing
            Constraint::Length(1), // User
            Constraint::Length(1), // Bulk
            Constraint::Min(0),    // Padding
        ])
        .split(inner);

    // Summary line
    let drain_time = state.tx_queue.estimated_drain_time_ms(state.airtime_per_byte_us);
    let summary = Line::from(vec![
        Span::styled("Depth: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", stats.depth),
            Style::default().fg(if stats.depth > 20 { Color::Red } else { Color::Cyan }),
        ),
        Span::raw("  "),
        Span::styled("Bytes: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{}", stats.bytes_pending)),
        Span::raw("  "),
        Span::styled("Drain: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{} ms", drain_time)),
    ]);
    f.render_widget(Paragraph::new(summary), inner_chunks[0]);

    // Priority breakdown
    let priorities = [
        ("Control", TxPriority::Control, Color::Red),
        ("Routing", TxPriority::Routing, Color::Yellow),
        ("User", TxPriority::User, Color::Cyan),
        ("Bulk", TxPriority::Bulk, Color::DarkGray),
    ];

    for (i, (name, prio, color)) in priorities.iter().enumerate() {
        let count = stats.by_priority[*prio as usize];
        let bar_len = count.min(20);
        let bar: String = (0..bar_len).map(|_| '\u{2588}').collect(); // Full block

        let line = Line::from(vec![
            Span::styled(format!("{:<8}", name), Style::default().fg(*color)),
            Span::styled(
                format!("{:>2}", count),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(*color)),
        ]);
        f.render_widget(Paragraph::new(line), inner_chunks[2 + i]);
    }
}

/// Format milliseconds as human-readable duration.
fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{} ms", ms)
    } else if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1} min", ms as f64 / 60_000.0)
    } else {
        format!("{:.1} h", ms as f64 / 3_600_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_ms_ranges() {
        assert_eq!(format_duration_ms(500), "500 ms");
        assert_eq!(format_duration_ms(1500), "1.5 s");
        assert_eq!(format_duration_ms(90_000), "1.5 min");
        assert_eq!(format_duration_ms(5_400_000), "1.5 h");
    }

    #[test]
    fn radio_state_initial() {
        let state = RadioState::new();
        assert!(state.now_ms > 0 || cfg!(not(debug_assertions)));
    }
}
