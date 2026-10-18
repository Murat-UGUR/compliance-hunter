"""Tag lifecycle: new / still / recovered hosts, tag clearing and FLAG_MISSING_DAT."""

import math

import mock_epo
from test_compliance_hunter import TAG, expected


def _split_fleet():
    fleet = mock_epo.build_fleet()
    stale = expected(fleet)
    compliant = sorted(d["EPOLeafNode.NodeName"] for d in fleet if d["EPOLeafNode.NodeName"] not in stale)
    return fleet, stale, compliant


def test_recovered_hosts_are_cleared_and_reported(base_env, run):
    fleet, stale, compliant = _split_fleet()
    still, recovered = stale[:5], compliant[:3]
    mock_epo.S.reset(pre_tagged=set(still) | set(recovered))

    p = run(base_env)
    assert p.returncode == 0, p.stderr
    # afterwards the tag means exactly "currently non-compliant"
    assert sorted(mock_epo.S.tags[TAG]) == stale
    assert sorted(n for batch in mock_epo.S.clear_calls for n in batch) == recovered
    # hosts that already carried the tag are not tagged again
    applied = {n for batch in mock_epo.S.apply_calls for n in batch}
    assert applied == set(stale) - set(still)

    wh = mock_epo.S.webhooks[0]
    assert (wh["new_count"], wh["still_count"], wh["recovered_count"]) == (len(stale) - 5, 5, 3)
    assert wh["recovered"] == recovered and wh["cleared"] == 3
    assert wh["tagged"] == len(stale)
    statuses = {d["hostname"]: d["status"] for d in wh["devices"]}
    assert all(statuses[h] == "still" for h in still)
    assert "düzeldi" in wh["text"]
    # new hosts are listed first in the chat preview
    first_line = wh["text"].split("\n\n", 1)[1].splitlines()[0]
    assert first_line.startswith("- 🆕 ")


def test_all_compliant_but_recovered_sends_all_clear(base_env, run):
    fleet, stale, compliant = _split_fleet()
    mock_epo.S.reset(fleet=[d for d in fleet if d["EPOLeafNode.NodeName"] in compliant], pre_tagged=compliant[:2])
    p = run(base_env)
    assert p.returncode == 0, p.stderr
    assert mock_epo.S.tags[TAG] == set()
    wh = mock_epo.S.webhooks[0]
    assert wh["count"] == 0 and wh["recovered_count"] == 2
    assert wh["text"].startswith("✅ Tüm cihazlar uyumlu")
    assert not mock_epo.S.apply_calls


def test_clear_recovered_can_be_disabled(base_env, run):
    fleet, stale, compliant = _split_fleet()
    mock_epo.S.reset(pre_tagged=compliant[:3])
    p = run({**base_env, "CLEAR_RECOVERED": "false"})
    assert p.returncode == 0
    assert not mock_epo.S.clear_calls
    assert set(compliant[:3]) <= mock_epo.S.tags[TAG]
    assert mock_epo.S.webhooks[0]["recovered_count"] == 0


def test_dry_run_does_not_clear(base_env, run):
    fleet, stale, compliant = _split_fleet()
    mock_epo.S.reset(pre_tagged=compliant[:3])
    p = run(base_env, "--dry-run")
    assert p.returncode == 0
    assert not mock_epo.S.clear_calls and not mock_epo.S.apply_calls and not mock_epo.S.webhooks
    assert "etiketi kaldırılacak" in p.stderr


def test_clearing_is_batched(base_env, run):
    fleet, stale, compliant = _split_fleet()
    recovered = compliant[:60]
    mock_epo.S.reset(pre_tagged=recovered)
    assert run(base_env).returncode == 0
    assert len(mock_epo.S.clear_calls) == math.ceil(60 / 50)
    assert all(len(b) <= 50 for b in mock_epo.S.clear_calls)
    assert mock_epo.S.webhooks[0]["cleared"] == 60


def test_failed_tag_query_never_clears(base_env, run):
    """If the tagged hosts cannot be read, nothing must be cleared (fail safe)."""
    fleet, stale, compliant = _split_fleet()
    mock_epo.S.reset(pre_tagged=compliant[:3], fail_tag_query=True)
    p = run(base_env)
    assert p.returncode == 1
    assert not mock_epo.S.clear_calls
    assert set(compliant[:3]) <= mock_epo.S.tags[TAG]
    assert set(stale) <= mock_epo.S.tags[TAG]  # tagging still happened
    assert any("hasTag" in e for e in mock_epo.S.webhooks[0]["errors"])


def test_failed_clear_batch_is_partial_failure(base_env, run):
    fleet, stale, compliant = _split_fleet()
    mock_epo.S.reset(pre_tagged=compliant[:60], fail_clear_batch=1)
    p = run(base_env)
    assert p.returncode == 1
    wh = mock_epo.S.webhooks[0]
    assert wh["cleared"] == 10 and any("clearTag" in e for e in wh["errors"])


def test_tag_query_uses_tag_id(state, base_env, run):
    run(base_env)
    queries = [a for c, a in state.calls if c == "core.executeQuery"]
    tag_query = queries[1]
    assert tag_query["where"] == f'(where (hasTag EPOLeafNode.AppliedTags "{state.tag_id(TAG)}"))'


def test_flag_missing_dat(state, base_env, run):
    p = run({**base_env, "FLAG_MISSING_DAT": "true"})
    assert p.returncode == 0
    q = next(a for c, a in state.calls if c == "core.executeQuery")
    assert "(isBlank EPOProdPropsView_VIRUSCAN.datdate)" in q["where"]
    assert "SRV-NOAV-01" in state.tags[TAG]  # recent check-in but no DAT date


def test_redirected_output_is_utf8(state, base_env, run, monkeypatch):
    """Logs redirected to a file (cron, Task Scheduler) keep Turkish characters on any code page.
    PYTHONIOENCODING=cp1252 reproduces a non-Turkish Windows server on every OS."""
    monkeypatch.setenv("PYTHONIOENCODING", "cp1252")
    p = run(base_env, "--dry-run")
    assert "ePO bağlantısı başarılı" in p.stderr
    assert "?" not in p.stderr.split("ePO ba", 1)[1].split(":", 1)[0]
