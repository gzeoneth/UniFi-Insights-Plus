# Browser preferences

Browsing choices are saved automatically in localStorage for this browser and app origin. They survive reloads and browser restarts. Another browser, profile, or hostname has separate settings. Clearing site data removes them.

| View | Remembered choices |
| --- | --- |
| App | Last tab, theme and settings section; explicit URL navigation takes precedence |
| Log Stream | Applied basic and advanced filters, custom dates, sorting, rows per page, visible columns, pause and filter panel state |
| Flow | Applied filters, actions/directions, custom dates, dimensions, top-N, graph/matrix panel, selected crossfilter/host, pair limit and filter panel state |
| Dashboard / Security | Shared relative time range |
| Threat map | Relative/custom time, mode, display type, camera position and expanded detail sections |
| Rule Usage | Applied filters and grouping |
| Firewall browser | IPv4/IPv6 and rule visibility filters, selected zone pair and expanded groups |
| View exclusions | Last applied profile and Show all; saved definitions reload by ID, while applied unsaved conditions stay local |

Relative ranges remain relative: selecting 24h means the latest 24 hours when the view next loads. An explicitly selected custom interval keeps its exact dates in that view. Existing session-only time and Flow settings migrate when no local preference exists. Explicit drilldowns replace conflicting remembered filters.

Malformed or unsupported stored values fall back to defaults. Blocked or full storage does not prevent the current page from working, but choices cannot be retained in that case. Data refresh still uses fresh requests or the existing short-lived session cache. Result rows, pagination cursors, fetched configuration, API keys, passwords and unsubmitted administrative form edits are not written to the preference records. Reading a remembered firewall view never reapplies a firewall action.

Saved server views and server settings retain their existing save behavior. Unsaved filter-editor changes take effect only after Apply filters. Local filter text can contain addresses or names entered by the user; use a separate browser profile on shared computers.

Use each view's Reset/Clear controls to remove its applied filters. This does not erase the underlying logs or change collection. Security remains independent of view-exclusion profiles.
