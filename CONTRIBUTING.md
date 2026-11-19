# Contributing

This fork revives HASSH after the original Salesforce repository was archived.
Contributions are welcome.

## New fingerprints

Fingerprints in `python/hasshGen/*.json` and `*.csv` are generated, not typed:

1. Add the implementation and version to `python/hasshGen/targets.json`
   (and a recipe in `hasshgen.py` if it is a new kind of software).
2. Run `python3 python/hasshGen/hasshgen.py -k <name>`; it builds the software
   in a container, captures the fingerprints and updates the database files.
3. Commit the database changes together with the target entry.

## Code

    cd python
    pip install -e '.[dev]'
    ruff check . && ruff format --check .
    pytest

The `hassh` package has no runtime dependencies; please keep it that way.
Any change to how `hassh` / `hasshServer` are composed needs a new
`hasshVersion` in both the Python and the Zeek implementation.
