"""Minimal mock of the Trellix ePO Web API (/remote/*) + a webhook receiver."""

import json
import random
import re
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, request
from werkzeug.serving import make_server

NOW = datetime.now(timezone.utc)
COLUMNS = {
    "EPOLeafNode.NodeName",
    "EPOLeafNode.LastUpdate",
    "EPOComputerProperties.IPAddress",
    "EPOProdPropsView_VIRUSCAN.datdate",
    "EPOLeafNode.AppliedTags",
}
TABLES = {"EPOLeafNode", "EPOComputerProperties", "EPOProdPropsView_VIRUSCAN"}


def build_fleet(n=200, seed=42):
    rnd = random.Random(seed)
    fleet = []
    for i in range(n):
        comm_age = rnd.choice([0, 1, 2, 3] * 6 + [8, 10, 15, 30])  # days
        dat_age = rnd.choice([0, 1, 2] * 6 + [9, 12, 20])
        dat = NOW - timedelta(days=dat_age, hours=2)
        fleet.append(
            {
                "EPOLeafNode.NodeName": f"WS-{i:04d}",
                "EPOComputerProperties.IPAddress": f"10.10.{i // 250}.{i % 250 + 1}",
                "EPOLeafNode.LastUpdate": NOW - timedelta(days=comm_age, hours=1),
                "EPOProdPropsView_VIRUSCAN.datdate": dat,
            }
        )
    # edge cases: no AV product (DAT null) but recent comm; and stale comm + no product
    fleet.append(
        {
            "EPOLeafNode.NodeName": "SRV-NOAV-01",
            "EPOComputerProperties.IPAddress": "10.20.0.1",
            "EPOLeafNode.LastUpdate": NOW - timedelta(hours=3),
            "EPOProdPropsView_VIRUSCAN.datdate": None,
        }
    )
    fleet.append(
        {
            "EPOLeafNode.NodeName": "SRV-NOAV-02",
            "EPOComputerProperties.IPAddress": "10.20.0.2",
            "EPOLeafNode.LastUpdate": NOW - timedelta(days=20),
            "EPOProdPropsView_VIRUSCAN.datdate": None,
        }
    )
    return fleet


class State:
    def __init__(self):
        self.reset()

    def reset(self, **kw):
        self.fleet = kw.get("fleet", build_fleet())
        self.user, self.password = "api_user", "s3cret"
        # tag name -> set of host names; tag IDs follow insertion order (like ePO's catalog)
        self.tags = {}
        if kw.get("tag_exists", True):
            self.tags["Other_Tag"] = set()  # so the tool's tag does not get ID 0 by accident
            self.tags["Outdated_DAT"] = set(kw.get("pre_tagged", ()))
            self.tags["Outdated_DAT_TEST"] = set()
        self.fail_apply_batch = kw.get("fail_apply_batch")  # 1-based batch number to fail
        self.fail_clear_batch = kw.get("fail_clear_batch")
        self.fail_tag_query = kw.get("fail_tag_query", False)
        self.http_500 = set(kw.get("http_500", ()))  # commands answered with HTTP 500 (real ePO does this)
        self.webhook_status = kw.get("webhook_status", 200)
        self.calls, self.webhooks, self.apply_calls, self.clear_calls = [], [], [], []

    def tag_id(self, name):
        return list(self.tags).index(name)

    def tag_name(self, tag_id):
        names = list(self.tags)
        return names[tag_id] if 0 <= tag_id < len(names) else None


S = State()
app = Flask(__name__)


def ok(obj):
    body = json.dumps(obj, default=lambda d: d.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return Response("OK:\n" + body, mimetype="text/plain")


def err(code, msg, http=200):
    return Response(f"Error {code} :\n{msg}", status=http, mimetype="text/plain")


@app.route("/remote/<cmd>")
def remote(cmd):
    a = request.authorization
    if not a or a.username != S.user or a.password != S.password:
        return Response("Unauthorized", status=401, mimetype="text/plain")
    args = request.args.to_dict()
    S.calls.append((cmd, args))
    if args.get(":output") != "json":
        return err(0, "expected :output=json")
    if cmd != "core.getSecurityToken" and args.get("orion.user.security.token") != "TOKEN123":
        return err(0, "missing/invalid security token")
    if cmd == "core.getSecurityToken":
        return ok("TOKEN123")
    if cmd in S.http_500 or (
        cmd == "core.executeQuery" and "hasTag" in args.get("where", "") and "hasTag" in S.http_500
    ):
        return err(0, f"Simulated server error in {cmd}", http=500)
    if cmd == "core.help":
        return ok("core.executeQuery target select where order group joinTables")
    if cmd == "core.executeQuery":
        return execute_query(args)
    if cmd == "system.findTag":
        q = args.get("searchText", "")
        return ok([{"tagId": S.tag_id(t), "tagName": t, "tagNotes": ""} for t in S.tags if q.lower() in t.lower()])
    if cmd == "system.applyTag":
        names = [n for n in args.get("names", "").split(",") if n]
        tag = args.get("tagName")
        S.apply_calls.append(names)
        if tag not in S.tags:
            return err(1, f"Tag not found: {tag}")
        if S.fail_apply_batch == len(S.apply_calls):
            return err(0, "Internal error while applying tag", http=500)
        known = {d["EPOLeafNode.NodeName"] for d in S.fleet}
        hit = [n for n in names if n in known]
        S.tags[tag].update(hit)
        return ok(len(hit))
    if cmd == "system.clearTag":
        names = [n for n in args.get("names", "").split(",") if n]
        tag = args.get("tagName")
        S.clear_calls.append(names)
        if tag not in S.tags:
            return err(1, f"Tag not found: {tag}")
        if S.fail_clear_batch == len(S.clear_calls):
            return err(0, "Internal error while clearing tag", http=500)
        hit = [n for n in names if n in S.tags[tag]]
        S.tags[tag].difference_update(hit)
        return ok(len(hit))
    return err(0, f"Unknown command: {cmd}")


def execute_query(args):
    target = args.get("target")
    if target not in TABLES:
        return err(0, f"Invalid target: {target}")
    sel = args.get("select", "")
    m = re.fullmatch(r"\(select ([^()]+)\)", sel.strip())
    if not m:
        return err(0, f"Bad select clause: {sel}")
    cols = m.group(1).split()
    joins = {t for t in args.get("joinTables", "").split(",") if t} | {target}
    for c in cols + re.findall(r"[A-Za-z_]+\.[A-Za-z_]+", args.get("where", "")):
        if c not in COLUMNS:
            return err(0, f"Unknown column: {c}")
        if c.split(".")[0] not in joins:
            return err(0, f"Table {c.split('.')[0]} not joined")
    where = args.get("where", "").strip()
    preds = []
    for col, ms in re.findall(r"\(olderThan ([\w.]+) (\d+)\)", where):
        preds.append(lambda r, c=col, m=ms: r[c] is not None and r[c] < NOW - timedelta(milliseconds=int(m)))
    for col in re.findall(r"\(isBlank ([\w.]+)\)", where):
        preds.append(lambda r, c=col: r[c] in (None, ""))
    for tag_id in re.findall(r'\(hasTag EPOLeafNode\.AppliedTags "(\d+)"\)', where):
        if S.fail_tag_query:
            return err(0, "Simulated failure of the hasTag query")
        name = S.tag_name(int(tag_id))
        members = S.tags.get(name, set()) if name else set()
        preds.append(lambda r, m=members: r["EPOLeafNode.NodeName"] in m)
    if where and not preds:
        return err(0, f"Unsupported where: {where}")
    is_or = where.startswith("(where (or")

    rows = []
    for r in S.fleet:
        res = [pred(r) for pred in preds]
        if not preds or (any(res) if is_or else all(res)):
            rows.append({c: r.get(c) for c in cols})
    om = re.fullmatch(r"\(order \((asc|desc) ([\w.]+)\)\)", args.get("order", "").strip())
    if om:
        rows.sort(key=lambda x: (x[om.group(2)] is None, x[om.group(2)] or NOW), reverse=om.group(1) == "desc")
    return ok(rows)


@app.route("/webhook", methods=["POST"])
def webhook():
    S.webhooks.append(request.get_json())
    return Response("ok", status=S.webhook_status)


def start(port):
    srv = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
