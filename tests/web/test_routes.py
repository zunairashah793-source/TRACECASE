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

def test_create_case_post_adapts_form_data_and_dictionary_result():
    app = create_app({"TESTING": True, "SECRET_KEY": "tracecase-test"})
    client = app.test_client()

    with patch(
        "tracecase.web.routes.create_case",
        return_value={"case_id": "case-route-test"},
    ) as mocked_create:
        response = client.post(
            "/cases/new",
            data={
                "title": "Route Integration Test",
                "description": "Testing the route boundary",
                "scope_description": "Authorized test scope",
                "notes": "Regression test",
            },
        )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/cases/case-route-test")

    payload = mocked_create.call_args.args[0]
    assert payload.title == "Route Integration Test"
    assert payload.description == "Testing the route boundary"
    assert payload.scope_description == "Authorized test scope"
    assert payload.notes == "Regression test"
