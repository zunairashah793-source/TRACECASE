
from flask import Blueprint, render_template

web = Blueprint(
    "web",
    __name__,
    static_folder="static",
    static_url_path="/web-static"
)

@web.route("/")
def dashboard():
    return render_template("dashboard.html")


@web.route("/cases")
def list_cases():
    return render_template("cases.html")
