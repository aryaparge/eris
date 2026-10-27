"""
Alert store for the ERIS analyst dashboard (SQLite, stdlib only).

alerts     one row per frame ERIS flagged as an attack
incidents  alerts grouped by (class, CAN ID) while the incident is open and active
events     audit trail: status changes, assignments, notes
"""
import sqlite3, threading, time

STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"]
OPEN = ("new", "acknowledged", "investigating")
GROUP_WINDOW_S = 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY, title TEXT, label TEXT, can_id TEXT,
  first_ts REAL, last_ts REAL, count INTEGER, severity TEXT, rank INTEGER,
  status TEXT, assignee TEXT, ack_ts REAL, closed_ts REAL);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, ts REAL, utr TEXT, can_id TEXT, label TEXT, confidence REAL,
  severity TEXT, rank INTEGER, score INTEGER, status TEXT, assignee TEXT,
  incident_id INTEGER, true_label TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL, alert_id INTEGER, incident_id INTEGER,
  actor TEXT, kind TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_alert_inc ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS ix_ev_inc ON events(incident_id);
"""


class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)

    def _rows(self, q, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def _event(self, actor, kind, detail, alert_id=None, incident_id=None, ts=None):
        self.conn.execute("INSERT INTO events(ts, alert_id, incident_id, actor, kind, detail) "
                          "VALUES (?,?,?,?,?,?)",
                          (ts or time.time(), alert_id, incident_id, actor, kind, detail))

    def reset(self):
        with self.lock:
            self.conn.executescript("DELETE FROM alerts; DELETE FROM incidents; DELETE FROM events;")
            self.conn.commit()

    # ------------------------------------------------------------ ingest
    def add_alert(self, a, title):
        """a: ts, utr, can_id, label, confidence, severity, rank, score, true_label, source.
        Returns (alert_id, incident_id, created_incident)."""
        with self.lock:
            c = self.conn
            inc = c.execute("SELECT * FROM incidents WHERE label=? AND can_id=? AND status IN "
                            "('new','acknowledged','investigating') AND last_ts>=? "
                            "ORDER BY id DESC LIMIT 1",
                            (a["label"], a["can_id"], a["ts"] - GROUP_WINDOW_S)).fetchone()
            created = inc is None
            if created:
                cur = c.execute("INSERT INTO incidents(title, label, can_id, first_ts, last_ts, count,"
                                " severity, rank, status) VALUES (?,?,?,?,?,1,?,?,'new')",
                                (title, a["label"], a["can_id"], a["ts"], a["ts"],
                                 a["severity"], a["rank"]))
                inc_id = cur.lastrowid
                self._event("ERIS", "opened", f"Incident opened: {title}", incident_id=inc_id, ts=a["ts"])
            else:
                inc_id = inc["id"]
                if a["rank"] > inc["rank"]:
                    c.execute("UPDATE incidents SET severity=?, rank=? WHERE id=?",
                              (a["severity"], a["rank"], inc_id))
                    self._event("ERIS", "escalated", f"Severity raised to {a['severity']}",
                                incident_id=inc_id, ts=a["ts"])
                c.execute("UPDATE incidents SET last_ts=?, count=count+1 WHERE id=?", (a["ts"], inc_id))
            status = "new" if created or inc["status"] == "new" else inc["status"]
            assignee = None if created else inc["assignee"]
            cur = c.execute("INSERT INTO alerts(ts, utr, can_id, label, confidence, severity, rank,"
                            " score, status, assignee, incident_id, true_label, source)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (a["ts"], a["utr"], a["can_id"], a["label"], a["confidence"],
                             a["severity"], a["rank"], a["score"], status, assignee, inc_id,
                             a.get("true_label"), a.get("source", "stream")))
            c.commit()
            return cur.lastrowid, inc_id, created

    # ------------------------------------------------------------ queries
    def list_alerts(self, status=None, severity=None, label=None, q=None, incident_id=None,
                    sort="ts", desc=True, limit=50, offset=0):
        where, args = [], []
        if status:
            where.append("status IN (%s)" % ",".join("?" * len(status))); args += status
        if severity:
            where.append("severity IN (%s)" % ",".join("?" * len(severity))); args += severity
        if label:
            where.append("label IN (%s)" % ",".join("?" * len(label))); args += label
        if incident_id:
            where.append("incident_id=?"); args.append(incident_id)
        if q:
            where.append("(utr LIKE ? OR can_id LIKE ? OR label LIKE ? OR assignee LIKE ?)")
            args += [f"%{q}%"] * 4
        w = ("WHERE " + " AND ".join(where)) if where else ""
        col = sort if sort in ("ts", "rank", "confidence", "label", "can_id", "status", "id") else "ts"
        total = self._rows(f"SELECT COUNT(*) n FROM alerts {w}", args)[0]["n"]
        rows = self._rows(f"SELECT * FROM alerts {w} ORDER BY {col} {'DESC' if desc else 'ASC'}, id DESC "
                          f"LIMIT ? OFFSET ?", args + [limit, offset])
        return total, rows

    def get_alert(self, aid):
        r = self._rows("SELECT * FROM alerts WHERE id=?", (aid,))
        if not r:
            return None
        a = r[0]
        a["incident"] = self.get_incident(a["incident_id"], with_events=False)
        a["events"] = self._rows("SELECT * FROM events WHERE alert_id=? OR (incident_id=? AND alert_id "
                                 "IS NULL) ORDER BY ts", (aid, a["incident_id"]))
        return a

    def list_incidents(self, status=None, limit=200):
        w, args = "", []
        if status:
            w = "WHERE status IN (%s)" % ",".join("?" * len(status)); args = list(status)
        return self._rows(f"SELECT * FROM incidents {w} ORDER BY (status IN "
                          f"('new','acknowledged','investigating')) DESC, rank DESC, last_ts DESC "
                          f"LIMIT ?", args + [limit])

    def get_incident(self, iid, with_events=True):
        r = self._rows("SELECT * FROM incidents WHERE id=?", (iid,))
        if not r:
            return None
        i = r[0]
        if with_events:
            i["events"] = self._rows("SELECT * FROM events WHERE incident_id=? ORDER BY ts", (iid,))
            i["by_status"] = {x["status"]: x["n"] for x in self._rows(
                "SELECT status, COUNT(*) n FROM alerts WHERE incident_id=? GROUP BY status", (iid,))}
        return i

    # ------------------------------------------------------------ analyst actions
    def update_alerts(self, ids, actor, status=None, assignee=None, note=None):
        if status and status not in STATUSES:
            raise ValueError("bad status")
        now = time.time()
        with self.lock:
            c = self.conn
            for aid in ids:
                a = c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
                if a is None:
                    continue
                if status and status != a["status"]:
                    c.execute("UPDATE alerts SET status=? WHERE id=?", (status, aid))
                    self._event(actor, "status", f"{a['status']} → {status}", alert_id=aid,
                                incident_id=a["incident_id"], ts=now)
                    inc = c.execute("SELECT * FROM incidents WHERE id=?", (a["incident_id"],)).fetchone()
                    if inc and inc["status"] == "new" and status != "new":
                        c.execute("UPDATE incidents SET status='acknowledged', ack_ts=? WHERE id=?",
                                  (now, inc["id"]))
                        self._event(actor, "status", "new → acknowledged (via alert)",
                                    incident_id=inc["id"], ts=now)
                if assignee is not None and assignee != a["assignee"]:
                    c.execute("UPDATE alerts SET assignee=? WHERE id=?", (assignee or None, aid))
                    self._event(actor, "assign", f"Assigned to {assignee or 'nobody'}",
                                alert_id=aid, incident_id=a["incident_id"], ts=now)
                if note:
                    self._event(actor, "note", note, alert_id=aid, incident_id=a["incident_id"], ts=now)
            c.commit()

    def update_incident(self, iid, actor, status=None, assignee=None, note=None):
        if status and status not in STATUSES:
            raise ValueError("bad status")
        now = time.time()
        with self.lock:
            c = self.conn
            inc = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
            if inc is None:
                return False
            if status and status != inc["status"]:
                ack = inc["ack_ts"] or (now if status != "new" else None)
                closed = now if status in ("resolved", "false_positive") else None
                c.execute("UPDATE incidents SET status=?, ack_ts=?, closed_ts=? WHERE id=?",
                          (status, ack, closed, iid))
                c.execute("UPDATE alerts SET status=? WHERE incident_id=? AND status IN "
                          "('new','acknowledged','investigating')", (status, iid))
                self._event(actor, "status", f"{inc['status']} → {status} (applied to open alerts)",
                            incident_id=iid, ts=now)
            if assignee is not None and assignee != inc["assignee"]:
                c.execute("UPDATE incidents SET assignee=? WHERE id=?", (assignee or None, iid))
                c.execute("UPDATE alerts SET assignee=? WHERE incident_id=?", (assignee or None, iid))
                self._event(actor, "assign", f"Assigned to {assignee or 'nobody'}", incident_id=iid, ts=now)
            if note:
                self._event(actor, "note", note, incident_id=iid, ts=now)
            c.commit()
            return True

    # ------------------------------------------------------------ summary
    def stats(self):
        r = lambda q, a=(): self._rows(q, a)
        by_status = {x["status"]: x["n"] for x in r("SELECT status, COUNT(*) n FROM alerts GROUP BY status")}
        by_sev = {x["severity"]: x["n"] for x in r(
            "SELECT severity, COUNT(*) n FROM alerts WHERE status IN ('new','acknowledged','investigating') "
            "GROUP BY severity")}
        by_label = {x["label"]: x["n"] for x in r("SELECT label, COUNT(*) n FROM alerts GROUP BY label")}
        inc = r("SELECT status, rank, first_ts, ack_ts FROM incidents")
        acks = [i["ack_ts"] - i["first_ts"] for i in inc if i["ack_ts"]]
        return {
            "alerts_total": sum(by_status.values()),
            "alerts_open": sum(by_status.get(s, 0) for s in OPEN),
            "by_status": by_status, "open_by_severity": by_sev, "by_label": by_label,
            "incidents_total": len(inc),
            "incidents_open": sum(i["status"] in OPEN for i in inc),
            "critical_open": sum(i["status"] in OPEN and i["rank"] == 4 for i in inc),
            "mtta_s": (sum(acks) / len(acks)) if acks else None,
        }

    def export(self):
        return self.list_incidents(limit=100000), self._rows("SELECT * FROM alerts ORDER BY ts"), \
            self._rows("SELECT * FROM events ORDER BY ts")
