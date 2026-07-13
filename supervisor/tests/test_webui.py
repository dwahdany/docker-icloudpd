"""Tests for icloudpd_supervisor.webui.

Hermetic: requests.Session is monkeypatched with an in-process fake that
replays HTML matching the *rendered* output of icloudpd 1.32.3's actual
server templates (src/icloudpd/server/templates/{code,password,no_input,
status}.html).  The markers the bridge keys on -- name="code",
name="password", <div class="fw-bold">error</div> -- are copied verbatim
from those templates.  No network, no real icloudpd.
"""

from __future__ import annotations

import pytest
import requests

import icloudpd_supervisor.webui as webui_mod
from icloudpd_supervisor.webui import WebUIBridge, WebUIState

USER = "user@example.com"

# Exact error string icloudpd sets on a rejected code
# (icloudpd/authentication.py request_2fa_web -> status_exchange.set_error).
REJECTED_CODE_ERROR = "Failed to verify two-factor authentication code"


# ---------------------------------------------------------------------------
# Rendered-template fixtures
# ---------------------------------------------------------------------------


def _jinja_escape(text: str) -> str:
    """Escape like markupsafe does for {{ error }} in Flask templates."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&#34;")
        .replace("'", "&#39;")
    )


def _error_block(error: str | None) -> str:
    """The {% if error %} block shared by code/password/no_input templates."""
    if error is None:
        return ""
    return f"""
        <ul class="list-group list-group-flush">
            <li class="list-group-item d-flex justify-content-between align-items-center">
                <div class="fw-bold">{_jinja_escape(error)}</div>
            </li>
        </ul>
"""


def code_page(error: str | None = None) -> str:
    """Rendered code.html: what /status returns while Status == NEED_MFA."""
    return f"""<form hx-post="/code" hx-swap="outerHTML" class="row align-items-center" hx-target-error="#toast-content">
    <fieldset>
        <legend>Authentication - {USER}</legend>
        {_error_block(error)}
        <div class="col-12 mb-3">
          <label for="code" class="form-label">Two-Factor code for {USER}</label>
          <input type="text" class="form-control" id="code" name="code" placeholder="Enter Two-Factor Code">
        </div>
        <div class="col-12">
            <button type="submit" class="btn btn-primary">Submit</button>
        </div>
    </fieldset>
</form>"""


def password_page(error: str | None = None) -> str:
    """Rendered password.html: /status output while Status == NEED_PASSWORD."""
    return f"""<form hx-post="/password" hx-swap="outerHTML" class="row align-items-center" hx-target-error="#toast-content">
    <fieldset>
        <legend>Authentication - {USER}</legend>
        {_error_block(error)}
        <div class="col-12 mb-3">
          <label for="password" class="form-label">Password for {USER}</label>
          <input type="password" class="form-control" id="password" name="password" placeholder="Enter password">
        </div>
        <div class="col-12">
            <button type="submit" class="btn btn-primary">Submit</button>
        </div>
    </fieldset>
</form>"""


def no_input_page(error: str | None = None) -> str:
    """Rendered no_input.html (condensed but structurally faithful).

    Note the template unconditionally renders
    <div class="fw-bold">No input is needed</div> and uses fw-bold for
    plain labels such as "Last Message"; the optional error block comes
    first in document order.
    """
    return f"""<div hx-get="/status" hx-trigger="every 5s" hx-swap="outerHTML">
    <div class="container-fluid">
        <div class="row mb-3">
            <div class="col-sm-6 col-xxl-4 mb-3 mb-sm-0">
                <div class="card">
                    <div class="card-header text-bg-primary">
                        Status - {USER}
                    </div>
                    {_error_block(error)}
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div class="fw-bold">No input is needed</div>
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-sm-6 col-xxl-4">
                <div class="card">
                    <div class="card-header text-bg-primary">
                        Photos Download - {USER}
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div class="fw-bold">Last Message</div>
                            <span>Downloaded 3 photos</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>"""


def checking_page(status_name: str = "CHECKING_MFA") -> str:
    """Rendered status.html: /status output for SUPPLIED_MFA / CHECKING_MFA."""
    return f"""<div hx-get="/status" hx-trigger="every 10s" hx-swap="outerHTML">
    <p>Status: {status_name}</p>
</div>"""


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, text: str = "", status_code: int = 200):
        self.text = text
        self.status_code = status_code


class FakeSession:
    """Stands in for requests.Session; records calls, replays scripted results.

    Scripted items are FakeResponse objects or Exception instances to raise.
    """

    def __init__(self):
        self.get_script = []
        self.post_script = []
        self.calls = []  # (method, url, data, timeout)

    def get(self, url, timeout=None):
        self.calls.append(("GET", url, None, timeout))
        return self._replay(self.get_script, url)

    def post(self, url, data=None, timeout=None):
        self.calls.append(("POST", url, data, timeout))
        return self._replay(self.post_script, url)

    @staticmethod
    def _replay(script, url):
        if not script:
            raise AssertionError(f"unexpected extra HTTP call to {url}")
        item = script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def fake_session(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(webui_mod.requests, "Session", lambda: session)
    return session


# ---------------------------------------------------------------------------
# status(): state classification
# ---------------------------------------------------------------------------


def test_code_page_classified_need_mfa(fake_session):
    fake_session.get_script.append(FakeResponse(code_page()))
    status = WebUIBridge().status()
    assert status.state is WebUIState.NEED_MFA
    assert status.error is None


def test_code_page_with_rejection_error(fake_session):
    fake_session.get_script.append(FakeResponse(code_page(error=REJECTED_CODE_ERROR)))
    status = WebUIBridge().status()
    assert status.state is WebUIState.NEED_MFA
    assert status.error == REJECTED_CODE_ERROR


def test_error_html_entities_are_unescaped(fake_session):
    # Jinja autoescapes {{ error }}; the bridge must undo that.
    raw = 'Apple said <no> & "denied" it\'s over'
    fake_session.get_script.append(FakeResponse(code_page(error=raw)))
    status = WebUIBridge().status()
    assert status.state is WebUIState.NEED_MFA
    assert status.error == raw


def test_password_page_classified_need_password(fake_session):
    fake_session.get_script.append(FakeResponse(password_page()))
    status = WebUIBridge().status()
    assert status.state is WebUIState.NEED_PASSWORD
    assert status.error is None


def test_password_page_with_error(fake_session):
    fake_session.get_script.append(
        FakeResponse(password_page(error="Invalid email/password combination."))
    )
    status = WebUIBridge().status()
    assert status.state is WebUIState.NEED_PASSWORD
    assert status.error == "Invalid email/password combination."


def test_no_input_page_classified_idle(fake_session):
    fake_session.get_script.append(FakeResponse(no_input_page()))
    status = WebUIBridge().status()
    assert status.state is WebUIState.IDLE


def test_no_input_page_error_is_suppressed(fake_session):
    # no_input.html uses fw-bold for unconditional labels, so error text
    # cannot be reliably extracted from IDLE pages; the bridge only reports
    # errors on prompt pages (NEED_MFA/NEED_PASSWORD).
    fake_session.get_script.append(
        FakeResponse(no_input_page(error="Failed to verify password"))
    )
    status = WebUIBridge().status()
    assert status.state is WebUIState.IDLE
    assert status.error is None


def test_no_input_page_without_error_reports_none(fake_session):
    fake_session.get_script.append(FakeResponse(no_input_page()))
    status = WebUIBridge().status()
    assert status.state is WebUIState.IDLE
    assert status.error is None


@pytest.mark.parametrize("status_name", ["SUPPLIED_MFA", "CHECKING_MFA"])
def test_intermediate_states_classified_checking(fake_session, status_name):
    # While icloudpd verifies a submitted code, /status renders status.html
    # ("Status: SUPPLIED_MFA" / "Status: CHECKING_MFA"). The bridge reports
    # CHECKING so the scheduler keeps waiting instead of declaring success
    # before Apple has actually accepted the code.
    fake_session.get_script.append(FakeResponse(checking_page(status_name)))
    status = WebUIBridge().status()
    assert status.state is WebUIState.CHECKING
    assert status.error is None


def test_unreachable_on_connection_error(fake_session):
    fake_session.get_script.append(
        requests.exceptions.ConnectionError("connection refused")
    )
    status = WebUIBridge().status()
    assert status.state is WebUIState.UNREACHABLE
    assert status.error is None


def test_unreachable_on_timeout(fake_session):
    fake_session.get_script.append(requests.exceptions.Timeout("timed out"))
    status = WebUIBridge().status()
    assert status.state is WebUIState.UNREACHABLE


def test_status_url_uses_host_and_port(fake_session):
    fake_session.get_script.append(FakeResponse(no_input_page()))
    WebUIBridge(port=9090, host="localhost").status()
    method, url, _, timeout = fake_session.calls[0]
    assert method == "GET"
    assert url == "http://localhost:9090/status"
    assert timeout == 10


# ---------------------------------------------------------------------------
# submit_code() / cancel()
# ---------------------------------------------------------------------------


def test_submit_code_accepted_on_200(fake_session):
    # POST /code returns 200 + code_submitted.html when set_payload succeeds.
    fake_session.post_script.append(FakeResponse("<div id=\"zone\">...</div>", 200))
    bridge = WebUIBridge()
    assert bridge.submit_code("123456") is True
    method, url, data, _ = fake_session.calls[0]
    assert (method, url) == ("POST", "http://127.0.0.1:8080/code")
    assert data == {"code": "123456"}


def test_submit_code_rejected_on_400(fake_session):
    # icloudpd answers 400 + auth_error.html when the payload is refused
    # (e.g. state was not NEED_MFA).
    fake_session.post_script.append(
        FakeResponse("<label class=\"form-label\">Wrong Two-Factor Code</label>", 400)
    )
    assert WebUIBridge().submit_code("000000") is False


def test_submit_code_false_when_unreachable(fake_session):
    fake_session.post_script.append(
        requests.exceptions.ConnectionError("connection refused")
    )
    assert WebUIBridge().submit_code("123456") is False


def test_cancel_posts_and_swallows_errors(fake_session):
    fake_session.post_script.append(
        requests.exceptions.ConnectionError("connection refused")
    )
    WebUIBridge().cancel()  # must not raise
    method, url, _, _ = fake_session.calls[0]
    assert (method, url) == ("POST", "http://127.0.0.1:8080/cancel")
