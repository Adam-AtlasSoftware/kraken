//! Reusable egui widgets for the KRAKEN GUI: theme, virtual list, hex view, decompiler text,
//! disassembly listing and control-flow graph view.

pub mod graph_view;
pub mod hex_view;
pub mod listing;
pub mod theme;
pub mod token_text;
pub mod virtual_list;

pub use graph_view::{
    BlockModel, CfgModel, EdgeKind, GraphToken, GraphView, GraphViewResponse, Viewport,
};
pub use hex_view::{ByteSource, ByteState, HexView, HexViewResponse, SliceSource};
pub use listing::{ListingResponse, ListingRow, ListingSource, ListingView, OperandToken, RowMark};
pub use theme::{KrakenTheme, Palette, TokenStyle};
pub use token_text::{TokenClick, TokenText, TokenTextResponse};
pub use virtual_list::{VirtualList, VirtualListResponse};
