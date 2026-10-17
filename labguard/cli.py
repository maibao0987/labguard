import argparse
import os

from alembic import command
from alembic.config import Config
from waitress import serve

from .app import ROOT, create_app
from .db import engine_for, seed


def migrate(service):
    os.environ["SERVICE"] = service
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(config, "head")
    seed(engine_for(), service)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "serve", "worker"])
    parser.add_argument(
        "--service", choices=["manager", "vulnerable", "fixed"], default=os.environ.get("SERVICE", "manager")
    )
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    if args.command == "init":
        migrate(args.service)
    elif args.command == "worker":
        from .worker import main as worker_main

        worker_main()
    else:
        serve(
            create_app(args.service),
            host="0.0.0.0" if args.container else "127.0.0.1",
            port=args.port,
            threads=4,
            max_request_body_size=128 * 1024,
            clear_untrusted_proxy_headers=True,
        )


if __name__ == "__main__":
    main()
