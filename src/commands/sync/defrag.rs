use std::{collections::BTreeMap, ops::Range};

use crossterm::event::KeyCode;
use futures_util::FutureExt;
use ratatui::{
    prelude::*,
    widgets::{Block, Paragraph},
};
use tokio::sync::mpsc;
use tracing::{error, info};
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerSmartWidget};
use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
use zcash_protocol::consensus::BlockHeight;

use crate::tui;

pub(super) struct AppHandle {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl AppHandle {
    /// Returns `true` if the TUI exited.
    pub(super) fn set_scan_ranges(
        &self,
        scan_ranges: &[ScanRange],
        chain_tip: BlockHeight,
    ) -> bool {
        match self.action_tx.send(Action::UpdateScanRanges {
            scan_ranges: scan_ranges.to_vec(),
            chain_tip,
        }) {
            Ok(()) => false,
            Err(e) => {
                error!("Failed to send: {}", e);
                true
            }
        }
    }

    /// Returns `true` if the TUI exited.
    pub(super) fn set_fetching_range(&self, fetching_range: Option<Range<BlockHeight>>) -> bool {
        match self.action_tx.send(Action::SetFetching(fetching_range)) {
            Ok(()) => false,
            Err(e) => {
                error!("Failed to send: {}", e);
                true
            }
        }
    }

    /// Returns `true` if the TUI exited.
    pub(super) fn set_scanning_range(&self, scanning_range: Option<Range<BlockHeight>>) -> bool {
        match self.action_tx.send(Action::SetScanning(scanning_range)) {
            Ok(()) => false,
            Err(e) => {
                error!("Failed to send: {}", e);
                true
            }
        }
    }
}

pub(super) struct App {
    should_quit: bool,
    wallet_birthday: BlockHeight,
    scan_ranges: BTreeMap<BlockHeight, ScanPriority>,
    fetching_range: Option<Range<BlockHeight>>,
    scanning_range: Option<Range<BlockHeight>>,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    logger_state: tui_logger::TuiWidgetState,
}

impl App {
    pub(super) fn new(wallet_birthday: BlockHeight) -> Self {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        Self {
            should_quit: false,
            wallet_birthday,
            scan_ranges: BTreeMap::new(),
            fetching_range: None,
            scanning_range: None,
            action_tx,
            action_rx,
            logger_state: tui_logger::TuiWidgetState::new(),
        }
    }

    pub(super) fn handle(&self) -> AppHandle {
        AppHandle {
            action_tx: self.action_tx.clone(),
        }
    }

    pub(super) async fn run(&mut self, mut tui: tui::Tui) -> anyhow::Result<()> {
        tui.enter()?;

        loop {
            let next_event = tui.next().fuse();
            let next_action = self.action_rx.recv().fuse();
            tokio::select! {
                Some(event) = next_event => if let Some(action) = Action::for_event(event) {
                    self.action_tx.send(action)?;
                },
                Some(action) = next_action => match action {
                    Action::Quit => {
                        info!("Quit requested");
                        self.should_quit = true;
                        break;
                    }
                    Action::Tick => {}
                    Action::LoggerEvent(event) => self.logger_state.transition(event),
                    Action::UpdateScanRanges { scan_ranges, chain_tip } => {
                        self.update_scan_ranges(scan_ranges, chain_tip);
                    }
                    Action::SetFetching(fetching_range) => self.fetching_range = fetching_range,
                    Action::SetScanning(scanning_range) => self.scanning_range = scanning_range,
                    Action::Render => {
                        tui.draw(|f| self.ui(f))?;
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }

        self.action_rx.close();
        tui.exit()?;

        Ok(())
    }

    fn update_scan_ranges(&mut self, mut scan_ranges: Vec<ScanRange>, chain_tip: BlockHeight) {
        scan_ranges.sort_by_key(|range| range.block_range().start);

        self.scan_ranges = scan_ranges
            .into_iter()
            .flat_map(|range| {
                [
                    (range.block_range().start, range.priority()),
                    // If this range is followed by an adjacent range, this will be
                    // overwritten. Otherwise, this is either a gap between unscanned
                    // ranges (which by definition is scanned), or the "mempool height"
                    // which we coerce down to the chain tip height.
                    (
                        range.block_range().end.min(chain_tip),
                        ScanPriority::Scanned,
                    ),
                ]
            })
            .collect();

        // If we weren't passed a ScanRange starting at the wallet birthday, it means we
        // have scanned that height.
        self.scan_ranges
            .entry(self.wallet_birthday)
            .or_insert(ScanPriority::Scanned);

        // If we inserted the chain tip height above, mark it as such. If we didn't insert
        // it above, do so here.
        self.scan_ranges
            .entry(chain_tip)
            .and_modify(|e| *e = ScanPriority::ChainTip)
            .or_insert(ScanPriority::ChainTip);
    }

    fn ui(&mut self, frame: &mut Frame) {
        let [upper_area, log_area] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(15)]).areas(frame.size());

        let defrag_area = {
            let block = Block::bordered().title("Wallet Defragmentor");
            let inner_area = block.inner(upper_area);
            frame.render_widget(block, upper_area);
            inner_area
        };

        if let Some(block_count) = self
            .scan_ranges
            .last_key_value()
            .map(|(&last, _)| u32::from(last - self.wallet_birthday))
        {
            // Determine the density of blocks we will be rendering.
            let blocks_per_cell = block_count / u32::from(defrag_area.area());
            let blocks_per_row = blocks_per_cell * u32::from(defrag_area.width);

            // Split the area into cells.
            for i in 0..defrag_area.width {
                for j in 0..defrag_area.height {
                    // Determine the priority of the cell.
                    let cell_start = self.wallet_birthday
                        + (blocks_per_row * u32::from(j))
                        + (blocks_per_cell * u32::from(i));
                    let cell_end = cell_start + blocks_per_cell;

                    let (cell_text, cell_color) = if self
                        .fetching_range
                        .as_ref()
                        .map(|range| range.contains(&cell_start) || range.contains(&(cell_end - 1)))
                        .unwrap_or(false)
                    {
                        ("↓", Color::Magenta)
                    } else if self
                        .scanning_range
                        .as_ref()
                        .map(|range| range.contains(&cell_start) || range.contains(&(cell_end - 1)))
                        .unwrap_or(false)
                    {
                        ("@", Color::Magenta)
                    } else {
                        let cell_priority = self
                            .scan_ranges
                            .range(cell_start..cell_end)
                            .fold(None, |acc: Option<ScanPriority>, (_, &priority)| {
                                if let Some(acc) = acc {
                                    Some(acc.max(priority))
                                } else {
                                    Some(priority)
                                }
                            })
                            .or_else(|| {
                                self.scan_ranges
                                    .range(..=cell_start)
                                    .next_back()
                                    .map(|(_, &priority)| priority)
                            })
                            .or_else(|| {
                                self.scan_ranges
                                    .range((cell_end - 1)..)
                                    .next()
                                    .map(|(_, &priority)| priority)
                            })
                            .unwrap_or(ScanPriority::Ignored);

                        (
                            " ",
                            match cell_priority {
                                ScanPriority::Ignored => Color::Black,
                                ScanPriority::Scanned => Color::Green,
                                ScanPriority::Historic => Color::Black,
                                ScanPriority::OpenAdjacent => Color::LightBlue,
                                ScanPriority::FoundNote => Color::Yellow,
                                ScanPriority::ChainTip => Color::Blue,
                                ScanPriority::Verify => Color::Red,
                            },
                        )
                    };

                    frame.render_widget(
                        Paragraph::new(cell_text).bg(cell_color),
                        Rect::new(defrag_area.x + i, defrag_area.y + j, 1, 1),
                    );
                }
            }
        }

        frame.render_widget(
            TuiLoggerSmartWidget::default()
                .style_error(Style::default().fg(Color::Red))
                .style_debug(Style::default().fg(Color::Green))
                .style_warn(Style::default().fg(Color::Yellow))
                .style_trace(Style::default().fg(Color::Magenta))
                .style_info(Style::default().fg(Color::Cyan))
                .output_separator(':')
                .output_timestamp(Some("%H:%M:%S".to_string()))
                .output_level(Some(TuiLoggerLevelOutput::Abbreviated))
                .output_target(true)
                .output_file(true)
                .output_line(true)
                .state(&self.logger_state),
            log_area,
        );
    }
}

#[derive(Clone, Debug)]
pub(super) enum Action {
    Quit,
    Tick,
    LoggerEvent(tui_logger::TuiWidgetEvent),
    UpdateScanRanges {
        scan_ranges: Vec<ScanRange>,
        chain_tip: BlockHeight,
    },
    SetFetching(Option<Range<BlockHeight>>),
    SetScanning(Option<Range<BlockHeight>>),
    Render,
}

impl Action {
    fn for_event(event: tui::Event) -> Option<Self> {
        match event {
            tui::Event::Error => None,
            tui::Event::Tick => Some(Action::Tick),
            tui::Event::Render => Some(Action::Render),
            tui::Event::Key(key) => match key.code {
                KeyCode::Char('q') => Some(Action::Quit),
                KeyCode::Char(' ') => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::SpaceKey))
                }
                KeyCode::Up => Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::UpKey)),
                KeyCode::Down => Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::DownKey)),
                KeyCode::Left => Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::LeftKey)),
                KeyCode::Right => Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::RightKey)),
                KeyCode::Char('+') => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::PlusKey))
                }
                KeyCode::Char('-') => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::MinusKey))
                }
                KeyCode::Char('h') => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::HideKey))
                }
                KeyCode::Char('f') => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::FocusKey))
                }
                KeyCode::PageUp => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::PrevPageKey))
                }
                KeyCode::PageDown => {
                    Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::NextPageKey))
                }
                KeyCode::Esc => Some(Action::LoggerEvent(tui_logger::TuiWidgetEvent::EscapeKey)),
                _ => None,
            },
            _ => None,
        }
    }
}