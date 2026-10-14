# How it works

1. `cli.py` reads a bounded JSON file or stdin. `scan -- ...` captures an explicitly requested WPScan process into a temporary file, avoiding shell interpolation.
2. `model.py` extracts scan intent before dropping the raw command line, normalizes inventory and preserves evidence. Unknown fields do not become false assurances. Active/parent themes and theme-enumeration results merge without discarding their separate evidence.
3. `render.py` uses Rich with literal Text objects for terminal output and escaped HTML for browser output. Version uncertainty, API data gaps and partial results remain visible.

WPScan changes over time. The formatter accepts absent optional fields and preserves component evidence, but only advertises CLI scope where original arguments are available. It doesn't infer complete coverage from the presence of a plugin or an empty vulnerability array.

HTML reports are standalone and can be opened directly. The normalized JSON intentionally omits the original command and known credential keys. Keep the original WPScan JSON privately if you need an exact archive.
