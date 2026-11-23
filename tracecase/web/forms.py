from dataclasses import dataclass


@dataclass
class ValidationResult:
    valid: bool
    data: dict
    errors: dict


def validate_case_form(form) -> ValidationResult:
    """
    Validate new case form input.
    """

    title = form.get("title", "").strip()
    description = form.get("description", "").strip()
    scope_description = form.get(
        "scope_description", ""
    ).strip()
    notes = form.get("notes", "").strip()

    errors = {}

    if not title:
        errors["title"] = "Title is required."

    elif len(title) > 200:
        errors["title"] = "Title cannot exceed 200 characters."

    if not scope_description:
        errors["scope_description"] = (
            "Scope description is required."
        )

    if len(scope_description) > 5000:
        errors["scope_description"] = (
            "Scope description is too long."
        )

    if len(description) > 10000:
        errors["description"] = (
            "Description is too long."
        )

    if len(notes) > 10000:
        errors["notes"] = "Notes are too long."

    data = {
        "title": title,
        "description": description or None,
        "scope_description": scope_description,
        "notes": notes or None,
    }

    return ValidationResult(
        valid=not errors,
        data=data,
        errors=errors,
    )


def validate_target_form(form) -> ValidationResult:
    """
    Validate target form input.

    Detailed indicator validation remains in the core validators.
    """

    indicator = form.get("indicator", "").strip()
    indicator_type = form.get(
        "indicator_type", ""
    ).strip()
    target_kind = form.get(
        "target_kind", ""
    ).strip()

    display_name = form.get(
        "display_name", ""
    ).strip()

    scope_note = form.get(
        "scope_note", ""
    ).strip()

    authorization_note = form.get(
        "authorization_note", ""
    ).strip()

    errors = {}

    if not indicator:
        errors["indicator"] = "Indicator is required."

    if not indicator_type:
        errors["indicator_type"] = (
            "Indicator type is required."
        )

    if not target_kind:
        errors["target_kind"] = (
            "Target kind is required."
        )

    if target_kind == "authorized_lab" and not scope_note:
        errors["scope_note"] = (
            "Authorized lab targets require a scope note."
        )

    data = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "target_kind": target_kind,
        "display_name": display_name or None,
        "scope_note": scope_note or None,
        "authorization_note": authorization_note or None,
    }

    return ValidationResult(
        valid=not errors,
        data=data,
        errors=errors,
    )