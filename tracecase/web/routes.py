from types import SimpleNamespace

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from tracecase.web.forms import validate_case_form

from tracecase.core.cases import (
    create_case,
    list_cases,
)
from tracecase.core.database import get_connection

web = Blueprint(
    "web",
    __name__,
    static_folder="static",
    static_url_path="/web-static",
)


@web.route("/")
def dashboard():
    cases = list_cases()

    # Dashboard metrics are read from the existing shared database schema.
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM cases) AS total_cases,
                (SELECT COUNT(*) FROM cases WHERE status = 'open')
                    AS open_cases,
                (SELECT COUNT(*) FROM cases WHERE status = 'closed')
                    AS closed_cases,
                (SELECT COUNT(*) FROM targets) AS total_targets,
                (SELECT COUNT(*) FROM findings) AS total_findings,
                (SELECT COUNT(*) FROM investigation_runs
                    WHERE status IN ('queued', 'running')) AS active_runs
            """
        ).fetchone()

    dashboard_stats = dict(row)

    return render_template(
        "ui_dashboard.html",
        dashboard_stats=dashboard_stats,
        recent_cases=cases[:5],
    )


@web.route("/cases")
def cases_page():
    cases = list_cases()

    return render_template(
        "ui_cases.html",
        cases=cases,
    )


@web.route("/cases/new", methods=["GET", "POST"])
def create_case_page():

    if request.method == "POST":

        result = validate_case_form(request.form)

        if not result.valid:
            return render_template(
                "case_form.html",
                data=result.data,
                errors=result.errors,
            ), 400

        try:
            case = create_case(SimpleNamespace(**result.data))

            flash("Case created successfully.", "success")

            return redirect(
                url_for(
                    "web.case_detail",
                    case_id=case["case_id"],
                )
            )

        except ValueError as exc:

            flash(str(exc), "error")

            return render_template(
                "case_form.html",
                data=result.data,
                errors={},
            ), 400

    return render_template(
        "case_form.html",
        data={},
        errors={},
    )


@web.route("/cases/<case_id>")
def case_detail(case_id):

    from tracecase.core.cases import get_case

    case = get_case(case_id)

    if case is None:
        return render_template(
            "404.html",
            message="Case not found.",
        ), 404

    return render_template(
        "case_detail.html",
        case=case,
    )


@web.errorhandler(404)
def not_found(error):

    return render_template(
        "404.html",
        message="Page not found.",
    ), 404
