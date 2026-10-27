import time
import uuid
from http.cookies import SimpleCookie

import pytest
import requests
from openhost_test_harness import OpenhostStack

SESSION_COOKIE = "mealie.access_token"
HTML = {"Accept": "text/html,application/xhtml+xml"}
# bootstrap_admin.py runs in the background after mealie's migrations; give it time on a slow runner.
BOOTSTRAP_DEADLINE_SECONDS = 300


def _context(stack: OpenhostStack, response: requests.Response | None) -> str:
    seen = "no response" if response is None else f"{response.status_code} {response.headers} {response.text[:500]}"
    return f"last response: {seen}\n\napp logs:\n{stack.app_logs()[-5000:]}"


def _get(session: requests.Session | None, url: str, **kwargs: object) -> requests.Response | None:
    try:
        return (session or requests).get(url, timeout=30, **kwargs)  # type: ignore[arg-type]
    except requests.ConnectionError:
        return None


@pytest.fixture(scope="module")
def owner_token(stack: OpenhostStack) -> str:
    """The Mealie token the auth proxy mints when the owner opens the app in a browser."""
    deadline = time.monotonic() + BOOTSTRAP_DEADLINE_SECONDS
    response = None
    while time.monotonic() < deadline:
        response = _get(stack.owner_session, f"{stack.url}/", headers=HTML, allow_redirects=False)
        if response is not None and response.status_code == 302:
            cookie = SimpleCookie(response.headers.get("Set-Cookie", ""))
            if SESSION_COOKIE in cookie:
                return cookie[SESSION_COOKIE].value
        time.sleep(3)
    pytest.fail(f"owner was never auto-logged in (no 302 setting {SESSION_COOKIE})\n{_context(stack, response)}")


def _api(stack: OpenhostStack, token: str) -> requests.Session:
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    return session


def test_owner_is_auto_logged_in_as_admin(stack: OpenhostStack, owner_token: str) -> None:
    response = _get(_api(stack, owner_token), f"{stack.url}/api/users/self")
    assert response is not None and response.status_code == 200, _context(stack, response)
    me = response.json()
    assert me["admin"] is True, f"auto-login user is not an admin: {me}"
    assert me["username"] == stack.owner_username, f"auto-login user isn't labelled as the owner: {me}"


def test_owner_bootstrap_replaced_the_seeded_admin(stack: OpenhostStack, owner_token: str) -> None:
    # While the seeded changeme@example.com admin exists, Mealie reports first login and the SPA bounces the owner
    # into the /admin/setup wizard on every visit.
    response = _get(_api(stack, owner_token), f"{stack.url}/api/app/about/startup-info")
    assert response is not None and response.status_code == 200, _context(stack, response)
    assert response.json()["isFirstLogin"] is False, f"owner still gets the first-login wizard: {response.text}"

    me = _api(stack, owner_token).get(f"{stack.url}/api/users/self", timeout=30).json()
    for email in ("changeme@example.com", me["email"]):
        login = requests.post(
            f"{stack.url}/api/auth/token", data={"username": email, "password": "MyPassword"}, timeout=30
        )
        assert login.status_code == 401, f"seeded password still logs in as {email}: {login.status_code} {login.text}"


def test_anonymous_cannot_reach_private_pages(stack: OpenhostStack, owner_token: str) -> None:
    page = requests.get(f"{stack.url}/", headers=HTML, allow_redirects=False, timeout=30)
    refused = page.status_code in (401, 403, 404) or (
        page.status_code in (302, 303, 307) and "/login" in page.headers.get("Location", "")
    )
    assert refused, f"anonymous GET / was not refused by the router: {page.status_code} {page.headers}"

    # /api/ is a public path at the router; mealie's own token auth has to refuse it.
    api = requests.get(f"{stack.url}/api/users/self", timeout=30)
    assert api.status_code == 401, f"anonymous /api/users/self: {api.status_code} {api.text[:300]}"

    about = requests.get(f"{stack.url}/api/app/about", timeout=30)
    assert about.status_code == 200, f"anonymous /api/app/about: {about.status_code} {about.text[:300]}"
    assert about.json()["allowSignup"] is False, f"open self-signup is enabled: {about.text}"


def test_anonymous_can_read_a_public_recipe(stack: OpenhostStack, owner_token: str) -> None:
    owner = _api(stack, owner_token)
    group_slug = owner.get(f"{stack.url}/api/groups/self", timeout=30).json()["slug"]
    created = owner.post(f"{stack.url}/api/recipes", json={"name": f"Shared soup {uuid.uuid4().hex[:8]}"}, timeout=30)
    assert created.status_code == 201, f"creating a recipe: {created.status_code} {created.text[:300]}"
    recipe_slug = created.json()

    # bootstrap_admin.py makes the default group and household public once; on a fresh Mealie they're private and
    # every public recipe link 404s.
    response = requests.get(f"{stack.url}/api/explore/groups/{group_slug}/recipes/{recipe_slug}", timeout=30)
    assert response.status_code == 200, f"anonymous public recipe: {response.status_code} {response.text[:300]}"
    assert response.json()["slug"] == recipe_slug

    page = requests.get(f"{stack.url}/g/{group_slug}/r/{recipe_slug}", headers=HTML, timeout=30)
    assert page.status_code == 200, f"anonymous public recipe page: {page.status_code} {page.text[:300]}"
