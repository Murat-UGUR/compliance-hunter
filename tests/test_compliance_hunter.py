import math
from datetime import timedelta

import mock_epo
from mock_epo import NOW

TAG = "Outdated_DAT"


def expected(fleet, days=7):
    lim = NOW - timedelta(days=days)
    return sorted(
        d["EPOLeafNode.NodeName"]
        for d in fleet
        if d["EPOLeafNode.LastUpdate"] < lim
        or (d["EPOProdPropsView_VIRUSCAN.datdate"] and d["EPOProdPropsView_VIRUSCAN.datdate"] < lim)
    )


def test_happy_path_tags_and_notifies(state, base_env, run):
    exp = expected(state.fleet)
    p = run(base_env)
    assert p.returncode == 0, p.stderr
    assert sorted(state.tags[TAG]) == exp
    assert len(state.apply_calls) == math.ceil(len(exp) / 50)
    assert all(len(b) <= 50 for b in state.apply_calls)
    wh = state.webhooks[0]
    assert wh["count"] == wh["tagged"] == len(wh["devices"]) == len(exp)
    assert wh["text"].startswith("⚠️ Dikkat")


def test_query_uses_or_and_milliseconds(state, base_env, run):
    run(base_env)
    q = next(a for c, a in state.calls if c == "core.executeQuery")
    assert q["where"].startswith("(where (or")
    assert q["where"].count("604800000") == 2


def test_stale_comm_without_av_is_found(state, base_env, run):
    run(base_env)
    assert "SRV-NOAV-02" in state.tags[TAG]


def test_known_gap_no_av_recent_comm_not_flagged(state, base_env, run):
    """Documented limitation: blank DAT date does not match olderThan."""
    run(base_env)
    assert "SRV-NOAV-01" not in state.tags[TAG]


def test_dry_run_changes_nothing(state, base_env, run):
    p = run(base_env, "--dry-run")
    assert p.returncode == 0
    assert not state.apply_calls and not state.webhooks


def test_missing_tag_reports_error(base_env, run):
    mock_epo.S.reset(tag_exists=False)
    p = run(base_env)
    assert p.returncode == 1
    wh = mock_epo.S.webhooks[0]
    assert wh["tagged"] == 0 and wh["errors"]


def test_partial_batch_failure_continues(base_env, run):
    mock_epo.S.reset(fail_apply_batch=1)
    exp = expected(mock_epo.S.fleet)
    p = run(base_env)
    assert p.returncode == 1
    assert len(mock_epo.S.tags[TAG]) == len(exp) - 50
    assert mock_epo.S.webhooks[0]["tagged"] == len(exp) - 50


def test_all_compliant_sends_nothing(base_env, run):
    full = mock_epo.build_fleet()
    mock_epo.S.reset(fleet=[d for d in full if d["EPOLeafNode.NodeName"] not in expected(full)])
    p = run(base_env)
    assert p.returncode == 0
    assert not mock_epo.S.webhooks and not mock_epo.S.apply_calls


def test_wrong_password_exit_3(state, base_env, run):
    assert run({**base_env, "EPO_PASSWORD": "wrong"}).returncode == 3


def test_unreachable_epo_exit_3(state, base_env, run):
    assert run({**base_env, "EPO_URL": "http://127.0.0.1:1"}).returncode == 3


def test_missing_env_exit_2_without_contacting_epo(state, base_env, run):
    env = {k: v for k, v in base_env.items() if k != "WEBHOOK_URL"}
    assert run(env).returncode == 2
    assert not state.calls


def test_bad_dat_column_exit_4(state, base_env, run):
    assert run({**base_env, "DAT_DATE_COLUMN": "wrongcol"}).returncode == 4


def test_webhook_failure_exit_5(base_env, run):
    mock_epo.S.reset(webhook_status=500)
    assert run(base_env).returncode == 5


def test_tag_name_read_from_dotenv(state, base_env, run):
    run({**base_env, "TAG_NAME": "Outdated_DAT_TEST"})
    used = [a.get("tagName") or a.get("searchText") for c, a in state.calls if c.startswith("system.")]
    assert used and all(u == "Outdated_DAT_TEST" for u in used)


def test_stale_days_read_from_dotenv(state, base_env, run):
    exp3 = expected(state.fleet, days=3)
    run({**base_env, "STALE_DAYS": "3"})
    assert state.webhooks[0]["count"] == len(exp3)
