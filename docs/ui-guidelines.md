# UI guidelines

Use Tabler 1.7.5 and Bootstrap 5.3 classes for UI markup. Prefer shared
`_components.html` macros: `page_header`, `card`, `data_table`,
`form_field`, `form_actions`, `modal`, `badge`, and `empty_state`.

- Put tables in `data_table(columns, body_id=none)`; provide `data-label` on
  cells where needed for mobile card layouts.
- Use `form_field` and `form_actions` for forms. Controls use `form-control`,
  `form-select`, and `form-check`.
- Buttons: `btn btn-primary` for primary actions, `btn` for default actions,
  and `btn btn-outline-danger` for destructive actions.
- Use Bootstrap spacing utilities such as `mb-3` and `gap-2`; do not use
  `style=""` attributes.
- Macro content is supplied through Jinja `{% call %}` blocks. `empty_state`
  may accept trusted template markup in `action_html`.
