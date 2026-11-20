"""Run the single-process orchestrator API."""
import os

import uvicorn

from .api import create_app


def main():
    uvicorn.run(create_app(), host=os.getenv("WGOCTOPUS_API_HOST", "127.0.0.1"), port=int(os.getenv("WGOCTOPUS_API_PORT", "8080")), workers=1)

if __name__ == "__main__": main()
