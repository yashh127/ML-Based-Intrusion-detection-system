"""NetShield IDS Dashboard — Flask entry point."""

import argparse
import os

from app.app import create_app


def main():
    """Parse arguments and run the Flask application."""
    parser = argparse.ArgumentParser(description="NetShield IDS Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Port to run on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--demo", action="store_true", help="Enable demo mode with simulated data")
    args = parser.parse_args()

    if args.demo:
        os.environ["IDS_DEMO_MODE"] = "1"

    app = create_app()
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
