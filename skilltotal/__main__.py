"""Enable ``python -m skilltotal`` as an entry point."""

from skilltotal.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
