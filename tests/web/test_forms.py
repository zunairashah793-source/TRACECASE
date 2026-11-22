from tracecase.web.forms import (
    validate_case_form,
    validate_target_form,
)


def test_valid_case_form():

    form = {
        "title": "Test Investigation",
        "description": "Test description",
        "scope_description": "Authorized test scope",
        "notes": "Test notes",
    }

    result = validate_case_form(form)

    assert result.valid is True
    assert result.errors == {}
    assert result.data["title"] == "Test Investigation"


def test_case_form_requires_title():

    form = {
        "title": "",
        "scope_description": "Authorized scope",
    }

    result = validate_case_form(form)

    assert result.valid is False
    assert "title" in result.errors


def test_case_form_requires_scope():

    form = {
        "title": "Test case",
        "scope_description": "",
    }

    result = validate_case_form(form)

    assert result.valid is False
    assert "scope_description" in result.errors


def test_case_title_limit():

    form = {
        "title": "A" * 201,
        "scope_description": "Authorized scope",
    }

    result = validate_case_form(form)

    assert result.valid is False
    assert "title" in result.errors


def test_valid_target_form():

    form = {
        "indicator": "192.168.56.101",
        "indicator_type": "ipv4",
        "target_kind": "authorized_lab",
        "display_name": "Lab VM",
        "scope_note": "Private test VM",
        "authorization_note": "Approved lab",
    }

    result = validate_target_form(form)

    assert result.valid is True
    assert result.data["indicator"] == "192.168.56.101"


def test_target_requires_indicator():

    form = {
        "indicator": "",
        "indicator_type": "ipv4",
        "target_kind": "external_public",
    }

    result = validate_target_form(form)

    assert result.valid is False
    assert "indicator" in result.errors


def test_lab_target_requires_scope_note():

    form = {
        "indicator": "192.168.56.101",
        "indicator_type": "ipv4",
        "target_kind": "authorized_lab",
        "scope_note": "",
    }

    result = validate_target_form(form)

    assert result.valid is False
    assert "scope_note" in result.errors