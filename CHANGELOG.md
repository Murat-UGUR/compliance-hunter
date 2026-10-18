# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Pending
- Validation against a live Trellix ePO server (run with `--dry-run -v` first).

## [0.2.0] - 2026-10-19

### Added
- Tag lifecycle: hosts that carry the tag are read with `hasTag` on `EPOLeafNode.AppliedTags`,
  classified as new / still / recovered; the tag is applied only to new hosts and cleared from
  recovered hosts with `system.clearTag` (`CLEAR_RECOVERED`, default `true`).
- Webhook payload: `new_count`, `still_count`, `recovered_count`, `cleared`, `recovered` and a
  per-device `status`; new hosts listed first; all-clear message when everything recovered.
- `FLAG_MISSING_DAT` to also flag hosts with an empty DAT date.
- `--version`.

### Fixed
- HTTP 4xx/5xx answers from ePO crashed the script with a traceback (no webhook): the real
  `mcafee-epo` client raises `requests.HTTPError` for them, but only `APIError` was handled.
  Network errors after connecting are handled the same way.
- HTTP 401/403 at connect time is reported as an authentication problem instead of
  "server unreachable".
- Log output redirected to a file (cron, Task Scheduler) is always UTF-8, so Turkish characters
  are no longer replaced by `?` on Windows servers with a non-Turkish code page.

### Changed
- `mcafee-epo` pinned to 1.1.0. Tests run against the real library; the shim is a fallback that
  mirrors it exactly.
- CI: Python 3.13, Windows, Node 24 based actions.

## [0.1.0] - 2026-10-03

### Added
- Daily check for hosts with a stale DAT or no agent check-in via `core.executeQuery`.
- `Outdated_DAT` tagging in batches of 50, JSON webhook alert, dry-run, exit codes.
- Mock ePO Web API and test suite; CI with ruff and pytest.
