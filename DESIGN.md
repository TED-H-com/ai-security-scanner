# App design system

This records the current desktop app. Product behavior is defined in
[docs/product-spec.md](docs/product-spec.md); CSS values remain authoritative in
[src/styles.css](src/styles.css) and the page stylesheets.

## 1. Visual theme

A compact work surface with dark teal navigation, pale surfaces and green primary
actions. Put the next useful action and scan outcome first. Optional configuration
and upstream evidence belong in expandable sections. Keep English and Traditional
Chinese and Japanese equally readable.

## 2. Color roles

| Role | Existing token / value |
| --- | --- |
| Text / strong text | `--ink` #17313a / `--ink-strong` #0e252d |
| Secondary text | `--muted` #57696f |
| Surface / soft surface | `--surface` #ffffff / `--surface-soft` #f7f8f5 |
| Border / strong border | `--line` #dce3df / `--line-strong` #c9d4cf |
| Navigation | `--sidebar` #102c37 |
| Primary action | `--accent-bright` #c9ef71 |
| Link / informational accent | `--teal` #1b7f7a / `--blue` #3478a4 |
| Warning / danger | `--amber` #ad6b16 / `--red` #b94642 |

Use the corresponding existing soft tokens for status backgrounds. Status also
needs text or a label, so color is never the only signal.

## 3. Typography

Reuse the Inter/system font stack with Segoe UI, Noto Sans TC, PingFang TC and
Microsoft JhengHei fallbacks. Existing page headings use
`clamp(1.55rem, 2vw, 2.1rem)` with 1.12 line height; introductory text uses 0.94rem
with 1.45 line height. Technical form copy uses 0.78rem. Preserve sibling styles
instead of introducing a new type scale. Wrap full URLs and identifiers without
discarding their content; do not apply Latin letter spacing to Chinese prose.

Japanese uses the same Latin/system stack, with Noto Sans JP, Hiragino Kaku Gothic
ProN, Yu Gothic and Meiryo fallbacks for Japanese glyph forms.

## 4. Components

Reuse `.button` with `--primary`, `--secondary`, `--ghost` or `--small` variants.
The base control has a 39px minimum height; the small variant uses 36px. One primary
action per section; optional checks use secondary actions. Keep field labels,
disabled/loading states and visible keyboard focus. Reuse `.field`, `.form-grid`,
`.scope-mode-card`, `.form-actions`, and expandable `.coverage-form-technical`
sections for scan inputs and consent.

## 5. Layout

Use the current page container (maximum 1560px), 272px sidebar, existing spacing
and responsive form grid. Related fields stay together. Radius tokens are 9px,
14px and 20px. Avoid nested cards and oversized inline actions. Long technical
values must wrap inside their container.

## 6. Depth

Use `--shadow-sm` for ordinary raised surfaces and `--shadow-md` for elevated
overlays. Existing borders provide most separation; do not add decorative shadows.

## 7. Guardrails

Reuse sibling classes and semantic tokens. Keep outcomes concise, preserve access
to evidence, and show explicit authorization beside network actions. Do not add
decorative gradients, invented statistics, new icon systems or a marketing hero
to app pages.

## 8. Responsive behavior

Respect existing 1250/1050/900/820/600px breakpoints in the app and page styles.
Navigation and grids collapse using those rules. Verify 390, 768 and 1440px widths
in all three languages, including populated long values. No horizontal page overflow;
preserve touch hit areas and readable inputs.

## 9. Implementation guide

For an optional scan input, reuse the Coverage expandable form and secondary
button. For a result, reuse the current summary and collapsed evidence components.
For a warning, reuse the existing status token and plain-language label. Build and
inspect rendered screenshots after changes; use real CSS and components in visual
fixtures, without contacting targets or entering real credentials.
