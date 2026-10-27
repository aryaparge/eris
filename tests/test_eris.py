"""ERIS checks: normalisation, classification, explanation, risk, alert workflow.

Run: .venv/bin/python -m pytest tests -q
"""
import os, sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard"))
import engine as E  # noqa: E402
from db import DB  # noqa: E402
from risk import RiskAssessor  # noqa: E402

SAMPLES = {  # Table 6.1
    "STEERING_WHEEL": "CAN_ID 080 D0 84 D1 03 D2 02 D3 23 D4 18 D5 05 D6 8A D7 22",
    "SPEED": "CAN_ID 158 D0 06 D1 1C D2 06 D3 3F D4 06 D5 2A D6 02 D7 29",
    "BENIGN": "CAN_ID 167 D0 00 D1 80 D2 00 D3 00 D4 00 D5 01 D6 E3 D7 00",
}


# ---------------------------------------------------------------- TC1-TC3: normalisation
@pytest.mark.parametrize("raw", ["2.0", "2", "02"])
def test_tc1_byte_normalisation(raw):
    assert E.norm_byte(raw) == "02"


def test_tc2_id_normalisation():
    assert E.norm_id("000001DC") == "1DC"


def test_tc3_utr_has_no_dlc_or_interface():
    utr, steps = E.normalise_raw("000001DC", ["2.0", "1E", "F5", "3", "0", "0", "0", "0"])
    assert utr == "CAN_ID 1DC D0 02 D1 1E D2 F5 D3 03 D4 00 D5 00 D6 00 D7 00"
    assert [s["field"] for s in steps] == E.FIELDS


def test_parse_utr_roundtrip():
    for utr in SAMPLES.values():
        assert E.utr_from_values(E.field_values(utr)) == utr


@pytest.mark.parametrize("bad", [("800", ["00"] * 8), ("1DC", ["00"] * 7), ("1DC", ["ZZ"] + ["00"] * 7)])
def test_invalid_frames_rejected(bad):
    with pytest.raises(ValueError):
        E.normalise_raw(*bad)


# ---------------------------------------------------------------- model + explanation
@pytest.fixture(scope="module")
def eng():
    e = E.get_engine()
    if e is None:
        pytest.skip("no trained model available")
    return e


def test_tc8_only_valid_labels(eng):
    for r in eng.classify(list(SAMPLES.values())):
        assert r["label"] in E.CLASSES
        assert abs(sum(r["probs"].values()) - 1) < 1e-4


def test_explanation_shape_and_completeness(eng):
    from explain import Reference, explain
    ex = explain(eng, Reference(eng.run_dir), SAMPLES["SPEED"])
    for k in ("occlusion", "integrated_gradients", "attention", "combined"):
        assert len(ex[k]) == 9
    assert abs(sum(ex["combined"]) - 1) < 1e-6
    # Integrated Gradients completeness: attributions sum to f(x) - f(baseline)
    assert ex["ig_check"]["completeness_error"] < 0.1 * max(1.0, abs(ex["ig_check"]["target_delta"]))
    assert ex["rationale"][0].startswith("ERIS classified this frame")


def test_counterfactual_flips_to_benign(eng):
    from explain import Reference, explain
    ref = Reference(eng.run_dir)
    for utr in (SAMPLES["SPEED"], SAMPLES["STEERING_WHEEL"]):
        cf = explain(eng, ref, utr)["counterfactual"]
        if cf.get("found"):
            assert eng.classify_one(cf["frame"])["label"] == "BENIGN"
            assert cf["changes"]


def test_benign_has_no_counterfactual(eng):
    from explain import Reference, explain
    ex = explain(eng, Reference(eng.run_dir), SAMPLES["BENIGN"])
    if ex["label"] == "BENIGN":
        assert ex["counterfactual"] == {"applicable": False}


# ---------------------------------------------------------------- risk
def test_risk_levels():
    r = RiskAssessor()
    assert r.static("BENIGN", 1.0, "167")["level"] == "None"
    assert r.static("STEERING_WHEEL", 0.99, "080")["level"] == "Critical"
    assert r.static("SPEED", 0.99, "158")["level"] == "High"
    assert r.static("RPM", 0.99, "1DC")["level"] == "Medium"
    assert r.static("RPM", 0.4, "1DC")["level"] == "Low"  # low confidence downgrades
    assert "0x080" in " ".join(r.static("STEERING_WHEEL", 0.99, "080")["actions"])


def test_sustained_attack_escalates():
    r = RiskAssessor()
    out = [r.assess("RPM", 0.99, "1DC", now=1000 + t * 0.5) for t in range(40)]
    assert out[0]["level"] == "Medium" and out[-1]["level"] == "High" and out[-1]["sustained"]


# ---------------------------------------------------------------- alert workflow
def _alert(ts, label="SPEED", can_id="158"):
    return {"ts": ts, "utr": SAMPLES["SPEED"], "can_id": can_id, "label": label, "confidence": 0.99,
            "severity": "High", "rank": 3, "score": 70, "true_label": label}


def test_alerts_group_into_incidents(tmp_path):
    db = DB(str(tmp_path / "t.db"))
    a1, i1, new1 = db.add_alert(_alert(100), "t")
    a2, i2, new2 = db.add_alert(_alert(110), "t")
    a3, i3, new3 = db.add_alert(_alert(500), "t")  # outside grouping window
    assert new1 and not new2 and new3 and i1 == i2 != i3
    assert db.get_incident(i1)["count"] == 2


def test_status_workflow_and_audit(tmp_path):
    db = DB(str(tmp_path / "t.db"))
    aid, iid, _ = db.add_alert(_alert(100), "t")
    db.update_alerts([aid], "tester", status="acknowledged", assignee="Arya", note="looking")
    a = db.get_alert(aid)
    assert a["status"] == "acknowledged" and a["assignee"] == "Arya"
    assert db.get_incident(iid)["status"] == "acknowledged"
    kinds = [e["kind"] for e in a["events"]]
    assert {"status", "assign", "note"} <= set(kinds)
    db.update_incident(iid, "tester", status="resolved")
    assert db.get_alert(aid)["status"] == "resolved"
    assert db.stats()["incidents_open"] == 0
    with pytest.raises(ValueError):
        db.update_alerts([aid], "tester", status="bogus")
