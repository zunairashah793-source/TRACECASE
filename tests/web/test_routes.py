from unittest.mock import patch

from tracecase import create_app


def test_dashboard_route():

    app = create_app(
        {"TESTING": True}
    )

    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200


def test_cases_route():

    app = create_app(
        {"TESTING": True}
    )

    client = app.test_client()

    response = client.get("/cases")

    assert response.status_code == 200


def test_create_case_get():

    app = create_app(
        {"TESTING": True}
    )

    client = app.test_client()

    response = client.get("/cases/new")

    assert response.status_code == 200


def test_unknown_route_returns_404():

    app = create_app(
        {"TESTING": True}
    )

    client = app.test_client()

    response = client.get("/this-route-does-not-exist")

    assert response.status_code == 404