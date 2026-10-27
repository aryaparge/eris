"""
ERIS risk assessment: severity of a detected attack for the vehicle.

Follows the ISO/SAE 21434 TARA idea of risk = impact x attack feasibility, then
adjusts for model confidence and for sustained attacks (same class firing repeatedly).
"""
import time
from collections import defaultdict, deque

LEVELS = ["None", "Low", "Medium", "High", "Critical"]

# impact and feasibility on a 1-4 scale (ISO/SAE 21434: negligible/moderate/major/severe,
# very low/low/medium/high)
PROFILE = {
    "BENIGN": {"function": "Normal vehicle traffic", "domain": "-", "impact": 0, "feasibility": 0,
               "impact_note": "No attack detected.", "actions": []},
    "DoS": {
        "function": "CAN bus availability (all ECUs)", "domain": "Safety + Operational",
        "impact": 4, "feasibility": 4,
        "impact_note": "High-priority flooding starves every ECU on the bus: brakes, steering "
                       "assist and powertrain messages can be delayed or lost.",
        "actions": ["Locate the flooding node (CAN ID 0x%s) and isolate its bus segment",
                    "Switch the gateway to fail-safe filtering for low-priority IDs",
                    "Advise the driver to stop safely if safety ECUs report timeouts"]},
    "STEERING_WHEEL": {
        "function": "Steering angle / lateral control (EPS, lane keeping)", "domain": "Safety",
        "impact": 4, "feasibility": 3,
        "impact_note": "Forged steering-angle frames can mislead power steering and lane-keeping "
                       "assist, a direct threat to vehicle control.",
        "actions": ["Disable ADAS lateral-control features that consume CAN ID 0x%s",
                    "Cross-check steering angle against yaw-rate and wheel-speed sensors",
                    "Escalate to the vehicle security operations lead immediately"]},
    "GAS": {
        "function": "Accelerator pedal / throttle position", "domain": "Safety",
        "impact": 4, "feasibility": 3,
        "impact_note": "Spoofed pedal position can cause unintended acceleration or loss of "
                       "throttle response.",
        "actions": ["Force limp-home torque limit on the engine controller",
                    "Validate pedal position against the redundant pedal sensor",
                    "Block further frames on CAN ID 0x%s at the gateway"]},
    "SPEED": {
        "function": "Vehicle speed signal (cluster, ABS/ESC, ADAS)", "domain": "Safety + Operational",
        "impact": 3, "feasibility": 3,
        "impact_note": "False speed values corrupt the instrument cluster and any ADAS or "
                       "stability function that relies on vehicle speed.",
        "actions": ["Fall back to wheel-speed sensors for speed-dependent functions",
                    "Flag the speedometer reading as untrusted to the driver",
                    "Capture traffic on CAN ID 0x%s for forensic analysis"]},
    "RPM": {
        "function": "Engine speed (RPM) signal", "domain": "Operational",
        "impact": 2, "feasibility": 3,
        "impact_note": "Forged RPM affects the tachometer and transmission shift logic; "
                       "mainly operational and driver-confusion risk.",
        "actions": ["Compare reported RPM with crankshaft sensor readings",
                    "Monitor transmission controller for abnormal shift requests",
                    "Capture traffic on CAN ID 0x%s for forensic analysis"]},
}

# ISO/SAE 21434-style risk matrix: impact (rows 1-4) x feasibility (cols 1-4) -> level 1-4
MATRIX = [[1, 1, 1, 2],
          [1, 2, 2, 3],
          [1, 2, 3, 4],
          [2, 3, 4, 4]]

WINDOW_S, BURST, SUSTAIN_S = 20.0, 30, 12.0


class RiskAssessor:
    def __init__(self):
        self.recent = defaultdict(deque)

    def assess(self, label, confidence, can_id, now=None):
        now = now or time.time()
        prof = PROFILE[label]
        if label == "BENIGN":
            return {"level": "None", "rank": 0, "score": 0, "function": prof["function"],
                    "domain": prof["domain"], "impact": 0, "feasibility": 0, "factors": [],
                    "impact_note": prof["impact_note"], "actions": []}
        base = MATRIX[prof["impact"] - 1][prof["feasibility"] - 1]
        rank, factors = base, [f"impact {prof['impact']}/4 x feasibility {prof['feasibility']}/4 "
                                 f"-> {LEVELS[base]}"]
        if confidence < 0.6:
            rank -= 1
            factors.append(f"low model confidence ({confidence:.0%}) -> downgraded one level")
        q = self.recent[label]
        q.append(now)
        while q and now - q[0] > WINDOW_S:
            q.popleft()
        sustained = len(q) >= BURST and now - q[0] >= SUSTAIN_S
        if sustained:
            rank += 1
            factors.append(f"sustained attack: {len(q)} {label} frames over {now - q[0]:.0f}s "
                           f"-> escalated one level")
        rank = max(1, min(4, rank))
        score = round(100 * (prof["impact"] * prof["feasibility"]) / 16 * (0.5 + 0.5 * confidence)
                      * (1.15 if sustained else 1.0))
        return {"level": LEVELS[rank], "rank": rank, "score": min(100, score),
                "function": prof["function"], "domain": prof["domain"],
                "impact": prof["impact"], "feasibility": prof["feasibility"],
                "sustained": sustained, "factors": factors, "impact_note": prof["impact_note"],
                "actions": [a % can_id if "%s" in a else a for a in prof["actions"]]}

    def static(self, label, confidence, can_id):
        """Assessment without updating the sliding window (inspector, details)."""
        saved = {k: deque(v) for k, v in self.recent.items()}
        out = self.assess(label, confidence, can_id)
        self.recent = defaultdict(deque, saved)
        return out
