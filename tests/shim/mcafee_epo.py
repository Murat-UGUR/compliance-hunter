"""Test shim reproducing the public interface of the `mcafee-epo` package
(Client(url, username, password, session=None), client(cmd, *args, **kwargs), APIError).
Lets the test suite run without the real package. Mirrors the library's behaviour:
GET {url}/remote/{cmd}?:output=json, basic auth, positional args -> paramN,
response 'OK:\n<json>' -> parsed json, anything else -> APIError."""

import json

import requests


class APIError(Exception):
    pass


class Client:
    def __init__(self, url, username, password, session=None):
        self._url = url.rstrip("/")
        self._auth = (username, password)
        self._session = session or requests.Session()
        self._token = None

    def _request(self, name, params):
        if self._token is None and name != "core.getSecurityToken":
            self._token = self._request("core.getSecurityToken", {})
        params = dict(params)
        params[":output"] = "json"
        if self._token:
            params["orion.user.security.token"] = self._token
        r = self._session.get(f"{self._url}/remote/{name}", auth=self._auth, params=params, timeout=10)
        status, _, result = r.text.partition(":")
        if status.strip() != "OK":
            raise APIError(r.text.strip())
        return json.loads(result.strip())

    def __call__(self, name, *args, **kwargs):
        params = {f"param{i + 1}": a for i, a in enumerate(args)}
        params.update(kwargs)
        return self._request(name, params)
