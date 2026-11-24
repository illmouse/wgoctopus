"""Run the single-process orchestrator API."""
import os
import sys

import uvicorn

from .api import create_app


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "import":
        from .importer import main as import_main
        return import_main(sys.argv[2:])
    uvicorn.run(create_app(), host=os.getenv("WGOCTOPUS_API_HOST", "127.0.0.1"), port=int(os.getenv("WGOCTOPUS_API_PORT", "8080")), workers=1)

if __name__ == "__main__": sys.exit(main())
