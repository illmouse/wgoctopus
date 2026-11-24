"""Run the single-process orchestrator API."""
import os
import sys

import uvicorn

from .api import create_app


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "import":
        from .importer import main as import_main
        return import_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "import-users":
        from .import_users import main as import_users_main
        return import_users_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "bootstrap":
        import argparse
        from pathlib import Path

        from .bootstrap import BootstrapError, apply_bootstrap, load_yaml
        from .config import database_url
        from .crypto import Crypto
        from .db import make_engine, make_session_factory, upgrade_to_head
        parser = argparse.ArgumentParser(prog="wgoctopus-orch bootstrap")
        parser.add_argument("--file", required=True)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--db", default=database_url())
        args = parser.parse_args(sys.argv[2:])
        try:
            upgrade_to_head(args.db)
            factory = make_session_factory(make_engine(args.db))
            report = apply_bootstrap(factory, load_yaml(Path(args.file).read_text()), crypto=Crypto(), dry_run=args.dry_run)
            for category in ("created", "updated", "unchanged", "pruned"):
                for kind, names in getattr(report, category).items():
                    print(f"{category}.{kind}: {len(names)} ({', '.join(names)})")
            return 0
        except BootstrapError as exc:
            print(f"validation_error: {', '.join(exc.errors)}")
            return 1
    uvicorn.run(create_app(), host=os.getenv("WGOCTOPUS_API_HOST", "127.0.0.1"), port=int(os.getenv("WGOCTOPUS_API_PORT", "8080")), workers=1)

if __name__ == "__main__": sys.exit(main())
