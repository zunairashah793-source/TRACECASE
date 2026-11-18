import os
from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get(
            "TRACECASE_SECRET_KEY",
            "development-only-change-before-use"
        ),
        DATABASE="instance/tracecase.sqlite3",
    )

    if test_config is not None:
        app.config.update(test_config)

    return app
