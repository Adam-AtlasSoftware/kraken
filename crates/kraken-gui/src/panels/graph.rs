//! The Graph tab: the function's basic blocks as boxes joined by arrows.

use egui::{RichText, Ui};
use kraken_gui_widgets::{BlockModel, CfgModel, EdgeKind, GraphView};
use kraken_viewmodel::{GraphData, GraphEdgeKind, ViewModel};

use super::PanelState;
use crate::style::{self, empty_state, medium, pal};
use crate::workspace::Tab;

/// The widget model of the last graph, rebuilt only when the graph's revision changes.
#[derive(Default)]
pub struct GraphUi {
    revision: Option<u64>,
    model: CfgModel,
}

/// Converts the view-model's graph into the widget's model.
pub fn model_of(data: &GraphData) -> CfgModel {
    CfgModel {
        blocks: data
            .blocks
            .iter()
            .map(|b| BlockModel {
                id: b.id,
                title: b.title.clone(),
                lines: b.lines.clone(),
            })
            .collect(),
        edges: data
            .edges
            .iter()
            .map(|(a, b, k)| {
                let kind = match k {
                    GraphEdgeKind::Fallthrough => EdgeKind::Fallthrough,
                    GraphEdgeKind::Jump | GraphEdgeKind::Switch => EdgeKind::Jump,
                    GraphEdgeKind::True => EdgeKind::ConditionalTrue,
                    GraphEdgeKind::False => EdgeKind::ConditionalFalse,
                };
                (*a, *b, kind)
            })
            .collect(),
        entry: data.entry,
    }
}

pub fn show(
    ui: &mut Ui,
    vm: &mut ViewModel,
    st: &mut PanelState,
    assist: &mut crate::assist::AssistUi,
) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    st.front = Some(Tab::Graph);
    let Some(name) = vm.current.as_ref().map(|c| c.name.clone()) else {
        empty_state(
            ui,
            "No graph to draw yet",
            "Pick a function and its code appears here as boxes joined by arrows.",
            Some("Tip: double-click a box to jump to its instructions."),
        );
        return;
    };
    vm.ensure_graph();

    ui.horizontal(|ui| {
        ui.label(medium(&name, 14.0).color(p.text_strong));
        let g = &vm.views.graph;
        if let Some(d) = &g.data {
            ui.label(
                RichText::new(format!("{} blocks", d.blocks.len()))
                    .size(12.0)
                    .color(p.text_dim),
            );
        } else if g.loading || vm.views.listing.loading {
            ui.spinner();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button("Listing  (Space)")
                .on_hover_text("See the same code as a plain list of instructions")
                .clicked()
            {
                st.swap_requested = true;
            }
        });
    });

    if let Some(err) = vm.views.graph.error.clone() {
        ui.label(RichText::new("The graph could not be drawn.").color(s.danger));
        ui.label(RichText::new(err).color(p.text_dim));
        if ui.button("Try again").clicked() {
            vm.retry_graph();
        }
        return;
    }
    if vm.views.graph.truncated {
        ui.label(
            RichText::new("This function is huge; only the first blocks are drawn.")
                .size(12.0)
                .color(s.warning),
        );
    }
    let Some(data) = vm.views.graph.data.as_ref() else {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Laying out the graph...").color(p.text_dim));
        });
        return;
    };
    if data.blocks.is_empty() {
        empty_state(
            ui,
            "No blocks here",
            "This function has no code of its own, so there is nothing to draw.",
            None,
        );
        return;
    }
    let revision = vm.views.graph.revision;
    if st.graph.revision != Some(revision) {
        st.graph.model = model_of(data);
        st.graph.revision = Some(revision);
    }
    let mut selected = vm.views.graph.selected;
    let out = GraphView::new(&st.graph.model)
        .id_salt("graph")
        .cache_id(revision)
        .show(ui, &mut selected);
    if out.changed
        && let Some(b) = selected
    {
        vm.graph_select(b);
    }
    if out.response.double_clicked()
        && let Some(b) = selected
    {
        vm.graph_open(b);
    }
    if out.response.secondary_clicked()
        && let Some(b) = selected
    {
        let line = vm
            .views
            .graph
            .data
            .as_ref()
            .and_then(|d| d.blocks.iter().find(|x| x.id == b))
            .map(|x| x.title.clone())
            .unwrap_or_default();
        crate::assist::capture_instruction_at(
            ui,
            out.response.rect,
            b,
            &line,
            vm.views.graph.function.or(vm.views.function),
            assist,
        );
    }
    if let Some(b) = selected {
        st.hot = Some(b);
    }
}

#[cfg(test)]
mod unit {
    use super::*;
    use kraken_viewmodel::GraphBlock;

    #[test]
    fn the_widget_model_keeps_blocks_edges_and_entry() {
        let data = GraphData {
            blocks: vec![
                GraphBlock {
                    id: 0x10,
                    end: 0x20,
                    title: "0x10".into(),
                    lines: vec![],
                },
                GraphBlock {
                    id: 0x20,
                    end: 0x30,
                    title: "0x20".into(),
                    lines: vec![],
                },
            ],
            edges: vec![
                (0x10, 0x20, GraphEdgeKind::True),
                (0x20, 0x10, GraphEdgeKind::Switch),
            ],
            entry: Some(0x10),
        };
        let m = model_of(&data);
        assert_eq!(m.blocks.len(), 2);
        assert_eq!(m.entry, Some(0x10));
        assert_eq!(m.edges[0].2, EdgeKind::ConditionalTrue);
        assert_eq!(m.edges[1].2, EdgeKind::Jump);
    }
}
