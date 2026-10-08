
from detector import detect_brute_force


def assess_ip_risk(timestamps):
    """
    Assess IP risk using failed login behavior.
    This is a heuristic, not a threat reputation lookup.
    """
    count = len(timestamps)

    if count == 0:
        return {
            "risk_level": "NONE",
            "risk_score": 0,
            "reason": "No failed login attempts"
        }

    brute_force = detect_brute_force(timestamps)

    if brute_force:
        return {
            "risk_level": "HIGH",
            "risk_score": 90,
            "reason": "Rapid repeated failed logins"
        }

    if count >= 5:
        return {
            "risk_level": "HIGH",
            "risk_score": 75,
            "reason": "High number of failed logins"
        }

    if count >= 3:
        return {
            "risk_level": "MEDIUM",
            "risk_score": 50,
            "reason": "Multiple failed login attempts"
        }

    return {
        "risk_level": "LOW",
        "risk_score": 20,
        "reason": "Few failed login attempts"
    }
