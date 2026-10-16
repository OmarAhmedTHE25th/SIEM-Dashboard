"""MITRE ATT&CK metadata used by detection rules."""

ATTACK = {
    "SSH_BRUTE_FORCE": ("T1110.001", "Brute Force: Password Guessing"),
    "SUCCESS_AFTER_MANY_FAILURES": ("T1078", "Valid Accounts"),
    "OFF_HOURS_LOGIN": ("T1078", "Valid Accounts"),
    "IMPOSSIBLE_TRAVEL": ("T1078", "Valid Accounts"),
    "CORR_COMPROMISE_SUSPECTED": ("T1078", "Valid Accounts"),
    "CORR_MULTI_STAGE_ATTACK": ("T1078", "Valid Accounts"),
    "CORR_ACCOUNT_TAKEOVER": ("T1078", "Valid Accounts"),
    "IOC_MATCH": ("T1588.006", "Vulnerability Research"),
    "SURICATA_ALERT": ("T1190", "Exploit Public-Facing Application"),
}

# Keep the tactic vocabulary stable so coverage reports can show capabilities
# that have no detections yet (rather than silently omitting them).
TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

TECHNIQUE_TACTICS = {
    "T1110.001": ("Credential Access",),
    "T1078": ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
    "T1588.006": ("Resource Development",),
    "T1190": ("Initial Access",),
}


def metadata(rule_name):
    """Return complete static ATT&CK metadata for a rule."""
    value = ATTACK.get(rule_name)
    if not value:
        return {}
    technique_id, technique_name = value
    return {
        "rule_name": rule_name,
        "mitre": technique_id,
        "mitre_technique": technique_id,
        "technique_name": technique_name,
        "tactics": list(TECHNIQUE_TACTICS.get(technique_id, ())),
    }


def lookup(rule_name):
    """Return ``(technique_id, technique_name)`` for a rule, if known."""
    value = ATTACK.get(rule_name)
    return ({"mitre_technique": value[0], "technique_name": value[1]}
            if value else {})
