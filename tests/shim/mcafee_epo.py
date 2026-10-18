"""Fallback stand-in for the `mcafee-epo` package (1.1.0), used only when the real package is not
installed. CI installs the real package (requirements-dev.txt), so this file is not what CI tests.

It mirrors the real library's behaviour, including the parts that matter for error handling:
  - GET {url}/remote/{cmd} built with urljoin, basic auth, ":output=json" and the security token
  - positional args -> param1, param2, ...
  - r.raise_for_status() FIRST: HTTP 4xx/5xx raise requests.HTTPError, not APIError
  - a 2xx body that does not start with "OK:" raises APIError
An earlier version turned every failure into APIError, which hid a crash on HTTP 500 responses.
"""

import json
from urllib.parse import urljoin

from requests import Session


class APIError(Exception):
    """An error with the data received within a valid HTTP response."""


class Client:
    def __init__(self, url, username, password, session=None):
        self.url = url
        self.username = username
        self.password = password
        self._session = session if session is not None else Session()
        self._token = None

    def _get_token(self, _skip=False):
        if self._token is None and not _skip:
            self._token = self._request("core.getSecurityToken")
        return self._token

    def _request(self, name, **kwargs):
        kwargs.setdefault("auth", (self.username, self.password))
        params = kwargs.setdefault("params", {})
        is_json = params.setdefault(":output", "json") == "json"
        params.setdefault("orion.user.security.token", self._get_token(_skip=name == "core.getSecurityToken"))
        url = urljoin(self.url, f"remote/{name}")
        if any(kwargs.get(key) for key in ("data", "json", "files")):
            r = self._session.post(url, **kwargs)
        else:
            r = self._session.get(url, **kwargs)
        r.raise_for_status()
        text = r.text
        if not text.startswith("OK:"):
            raise APIError(text)
        return json.loads(text[3:]) if is_json else text[3:]

    def __call__(self, name, *args, **kwargs):
        params = kwargs.pop("params", {})
        files = kwargs.pop("files", {})
        for i, item in enumerate(args, start=1):
            params[f"param{i}"] = item
        params.update(kwargs)
        return self._request(name, params=params, files=files)
