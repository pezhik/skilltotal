"""Enable ``python -m skilltotal`` as an entry point."""

from skilltotal.hook_fast import main

if __name__ == "__main__":
    raise SystemExit(main())
