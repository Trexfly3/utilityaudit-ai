from pathlib import Path

from conftest import TEST_PASSWORD
from streamlit.testing.v1 import AppTest

from utilityaudit.auth import Auth
from utilityaudit.database import runtime_database
from utilityaudit.storage import Repository


def button(app, label):
    return next(item for item in app.button if item.label == label)


def signed_in_app(tmp_path, monkeypatch):
    monkeypatch.setenv("UTILITYAUDIT_DATA_DIR", str(tmp_path))
    database = runtime_database()
    identity, organization_id = Auth(database).bootstrap("test-owner", TEST_PASSWORD, "UI Test")
    repo = Repository(database, identity, organization_id)
    app = AppTest.from_file(Path("app.py").resolve(), default_timeout=30).run()
    assert not app.exception
    app.text_input[0].set_value("test-owner")
    app.text_input[1].set_value(TEST_PASSWORD)
    button(app, "Sign in").click().run()
    assert not app.exception
    return app, repo


def test_uninitialized_app_has_no_default_access(tmp_path, monkeypatch):
    monkeypatch.setenv("UTILITYAUDIT_DATA_DIR", str(tmp_path))
    app = AppTest.from_file(Path("app.py").resolve(), default_timeout=30).run()
    assert not app.exception
    assert not app.metric and not app.sidebar.radio
    assert any("operator" in item.value for item in app.info)


def test_empty_dashboard_and_pages(tmp_path, monkeypatch):
    app, repo = signed_in_app(tmp_path, monkeypatch)
    assert app.metric[0].value == "0"
    for page in ("Upload Bills", "Bill History", "Audit Findings", "Reports", "Settings"):
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, page
    button(app, "Sign out").click().run()
    assert not app.exception and not app.metric
    repo.db.engine.dispose()


def test_populated_pages_run_and_save_settings(tmp_path, monkeypatch):
    app, repo = signed_in_app(tmp_path, monkeypatch)
    repo.import_document("sample.csv", Path("samples/bills.csv").read_bytes())
    app.run()
    assert app.metric[0].value == "4"
    button(app, "Run audit").click().run()
    assert len(repo.recent_runs()) == 1
    for page in ("Upload Bills", "Bill History", "Audit Findings", "Reports", "Settings"):
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, page
        if page == "Reports":
            button(app, "Generate downloadable reports").click().run()
            assert not app.exception
            assert len(app.get("download_button")) == 2
    next(item for item in app.number_input if item.label == "Bill increase threshold (%)").set_value(45.0)
    button(app, "Save thresholds").click().run()
    assert repo.config().bill_increase_pct == 45.0
    app.sidebar.radio[0].set_value("Upload Bills").run()
    next(item for item in app.checkbox if item.label.startswith("Permanently remove")).check().run()
    button(app, "Remove document").click().run()
    assert not app.exception and not repo.bills()


def test_correction_and_finding_review_ui(tmp_path, monkeypatch):
    app, repo = signed_in_app(tmp_path, monkeypatch)
    repo.import_document("sample.csv", Path("samples/bills.csv").read_bytes())
    app.sidebar.radio[0].set_value("Audit Findings").run()
    next(item for item in app.selectbox if item.label == "Review decision").set_value("dismissed")
    # Select a visible finding form by its field labels rather than widget positions.
    next(item for item in app.text_area if item.label == "Source evidence and reasoning").set_value(
        "Reviewed source; this is a synthetic development fixture."
    )
    button(app, "Save review").click().run()
    assert not app.exception
    assert any(item.review_version == 1 and item.review_status == "dismissed" for item in repo.analysis()[1].findings)
    app.sidebar.radio[0].set_value("Bill History").run()
    next(item for item in app.checkbox if item.label == "Open sensitive source review").check().run()
    next(item for item in app.selectbox if item.label == "Field to correct or verify").set_value("total_due").run()
    next(item for item in app.text_area if item.label.startswith("Corrected value")).set_value("151")
    next(item for item in app.text_area if item.label == "Correction reason and source evidence").set_value(
        "Verified corrected total in source CSV row 2."
    )
    next(item for item in app.checkbox if item.label.startswith("I checked")).check()
    button(app, "Save correction / verification").click().run()
    assert not app.exception
    assert repo.bills()[0].version == 2
