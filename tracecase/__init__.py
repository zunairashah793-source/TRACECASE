
import os

from flask import Flask

from tracecase.core.database import initialize_database


def create_app(test_config=None):
    app = Flask(
        __name__,
        template_folder="templates",
        instance_path=os.path.abspath("instance")
    )

    app.config.from_mapping(
        SECRET_KEY=os.environ.get(
            "TRACECASE_SECRET_KEY",
            "development-only-change-before-use"
        ),
        DATABASE="instance/tracecase.sqlite3",
    )

    if test_config is not None:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize the existing SQLite schema before serving requests.
    initialize_database()

    from tracecase.web.routes import web

    app.register_blueprint(web)

    return app
