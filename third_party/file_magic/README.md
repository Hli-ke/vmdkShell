Vendored subset of upstream `file` / `libmagic` rule sources.

Source:
- https://github.com/file/file

Included files:
- `COPYING`
- `README.upstream.md`
- `Magdir/linux`
- `Magdir/compress`
- `Magdir/archive`

Current local engine:
- Implemented in `tools/magic_engine.py`
- Supports only a small syntax subset needed by this project
- Falls back to built-in heuristics when no vendored rule matches

This directory is intended for local reuse of upstream rule text, not a full
copy of the upstream implementation.
