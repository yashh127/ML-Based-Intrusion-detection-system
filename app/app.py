"""Flask application factory for NetShield IDS Dashboard."""

from pathlib import Path
from flask import Flask


def create_app():
    """Create and configure the Flask application."""
    app_dir = Path(__file__).resolve().parent
    static_dir = app_dir / "static"
    template_dir = app_dir / "templates"

    app = Flask(
        __name__,
        static_folder=str(static_dir),
        template_folder=str(template_dir),
    )

    app.config["SECRET_KEY"] = "netshield-ids-secret-key-change-in-production"

    from app.routes import bp as routes_bp

    app.register_blueprint(routes_bp)

    return app
