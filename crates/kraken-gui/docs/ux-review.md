# GUI usability review

Reviewed as a design reviewer for a developer who is new to reverse engineering. Scenes: the demo
project, a real project (`pie_list-O0` through a private-runtime `krakend` with real Ghidra), the
welcome screen, the palette, graph, agents and rewrite scenes, and both themes. Screenshots are
`docs/screenshot*.png` (refreshed: `screenshot.png`, `screenshot-light.png`, `screenshot-welcome.png`).
Status: FIXED means changed in this pass; OPEN means left for a follow-up (needs data, registry or
daemon changes, or a larger redesign).

## Ranked findings

1. **First screen gave a newcomer no starting point (welcome).** The demo, the best first step,
   was the last card and a plain unframed button; nothing said what a "project" is. FIXED: the demo
   card moves to the top, with the accent button, while the recent-projects list is empty; a one-line
   explanation of a project sits under the tagline. (`screenshot-welcome.png`)
2. **Command palette mixed two vocabularies.** Curated rows read "Rename this function" while the
   rest showed raw registry names (`rename_symbol`, `rewrite_plan`, `project_open`). FIXED: rows
   made from commands read as words ("Rename symbol"); the raw name still matches typed queries, so
   developers lose nothing.
3. **"1 edit" in the status bar was jargon and a dead label.** FIXED: "No changes yet", "1 change",
   "5 changes", with a tooltip pointing to the History tab; the "to review" chip says what to do
   with proposals.
4. **Progress bar text was cramped and low contrast.** White text on a bright accent fill and a
   190 px bar clipped "Analyzing: load". FIXED: wider bar, softer fill, theme text colour; the
   status-bar spinner no longer touches the window edge.
5. **Theme button named the other theme ("Light") with no hint it was a toggle.** FIXED: "Light
   theme"/"Dark theme" and a tooltip saying the choice is remembered. Learn mode now reads
   "Learn mode: on" when active, so its state is visible without relying on the highlight alone.
6. **Disabled "Create project and analyze" gave no reason.** FIXED: hover text says whether a program
   or a folder fix is missing.
7. **Function list mixes imports and thunks with real functions (real project).** `free`, `printf`,
   `_init` and PLT stubs sit among program code with nothing to separate them. OPEN: needs a
   per-function kind (external/thunk) in the view model data; the list could group or dim them, and
   offer "hide library stubs".
8. **Long decompiler lines are clipped with no cue (real project, the "WARNING: Unknown calling
   convention" comment).** OPEN: wrap comment lines or show a horizontal scroll indicator; this is a
   widget change in `kraken-gui-widgets` token text.
9. **Callers (0) is the tab shown by default and is often empty.** The empty message is good ("Nothing
   calls this function") but a newcomer sees an apparent dead end while Calls has entries. OPEN:
   default to whichever side has entries.
10. **Toasts cover the bottom of the listing and hex views** until dismissed or timed out. OPEN:
    anchor them above the status bar over the least used panel, or shift upward when the right dock
    is bottom-aligned.
11. **Duplicate entry points for the assistant** (top-bar button and an Assistant tab) and for
    rewrite ("Rewrite in Rust" button, Rewrite tab, plus palette commands). Consistent enough, but
    the tab and button have different labels in the agents scene. OPEN: pick one wording.
12. **Keyboard.** The palette (Ctrl+K), rename (N), back/forward (Alt+Arrows), filter (Ctrl+L),
    cross-references (X) and settings (Ctrl+,) are all reachable and tested; Escape closes dialogs.
    Gaps, OPEN: no visible focus ring distinction on the tab strip, and the dock tabs cannot be
    switched from the keyboard (suggest Ctrl+Tab and Ctrl+1..n).
13. **Contrast.** Dark theme is fine. Light theme dim text (`text_dim` on `surface`) is near 4.5:1 for
    11 px captions such as the hex column heads; acceptable for body text, borderline for the
    smallest captions. OPEN: raise `text_dim` slightly in the light palette.
14. **Empty states are good and consistent** (title, plain sentence, an accent tip). No change; this
    is the pattern the welcome and palette fixes follow.

## Not changed on purpose

Registry commands and daemon behaviour (out of scope), and the dock layout, which tests and docs
screenshots rely on.
