from __future__ import annotations

import json
import os
import signal
import sys
import threading

from lab_dashboard.app import create_server
from lab_dashboard.config import ConfigurationError, load_config


def log(event: str, **details: object) -> None:
    print(json.dumps({"event": event, **details}, separators=(",", ":")), flush=True)


def main() -> int:
    try:
        config = load_config()
        port = int(os.environ.get("DASHBOARD_PORT", "3000"))
    except (ConfigurationError, ValueError) as error:
        log("startup_failed", reason=str(error))
        return 1

    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    try:
        server = create_server(config, (host, port))
    except (OSError, ValueError) as error:
        log("startup_failed", reason=type(error).__name__)
        return 1

    def stop(_signal_number: int, _frame: object) -> None:
        log("shutdown_requested")
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log("dashboard_started", address=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    log("dashboard_stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
