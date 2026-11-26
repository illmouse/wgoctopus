# UI guidelines

| Element | Macro / class |
|---|---|
| Page title and actions | `page_header(title, subtitle=none)` |
| Card | `card(title=none)` |
| Table | `data_table(columns)` + `.table-wrap`, `.data-table` |
| Field / form grid / actions | `form_field(...)`, `.form-row`, `form_actions()` |
| Buttons in a row | `.btn-row` (also used by `form_actions()`) |
| Modal | `modal(id, title)` + `.dialog-actions` |
| Label, empty content, toolbar | `badge(...)`, `empty_state(...)`, `.toolbar` |
| Vertical stack | `.stack` |
| Action cells | `.cell-actions` |

`page_header`, `card`, `data_table`, `form_field`, `form_actions`, and `modal`
accept their content through a Jinja `{% call %}` block. Put modal buttons in
`.dialog-actions` inside the modal caller block. `empty_state` optionally accepts
HTML in `action_html`; it is trusted template markup.

Rules:
1. All tables use `data_table`; cells provide `data-label` for mobile cards.
2. All forms use `form_field` for controls and `form_actions` for their buttons.
3. CSS spacing uses only `--space-1` through `--space-8` (4, 8, 12, 16, 24, 32,
   48, 64px); do not add ad-hoc spacing values.

To add a page, import the needed macros from `_components.html`, use
`page_header` and `card` for its structure, put every table in `data_table`,
and group fields/actions with the form macros and classes above.
