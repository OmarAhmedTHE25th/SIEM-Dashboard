"""MITRE ATT&CK metadata used by detection rules."""

ATTACK = {
    "SSH_BRUTE_FORCE": ("T1110.001", "Brute Force: Password Guessing"),
    "SUCCESS_AFTER_MANY_FAILURES": ("T1078", "Valid Accounts"),
    "OFF_HOURS_LOGIN": ("T1078.003", "Valid Accounts: Local Accounts"),
    "IMPOSSIBLE_TRAVEL": ("T1078,T1133", "Valid Accounts, External Remote Services"),
    "CORR_COMPROMISE_SUSPECTED": (
        "T1110.001,T1078",
        "Brute Force: Password Guessing -> Valid Accounts",
    ),
    "CORR_MULTI_STAGE_ATTACK": (
        "T1190,T1071",
        "Exploit Public-Facing Application -> Application Layer Protocol",
    ),
    "CORR_ACCOUNT_TAKEOVER": ("T1078,T1133", "Valid Accounts, External Remote Services"),
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
    "T1078.003": ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
    "T1133": ("Persistence", "Initial Access"),
    "T1588.006": ("Resource Development",),
    "T1190": ("Initial Access",),
    "T1071": ("Command and Control",),
}


def _technique_ids(value):
    return [technique.strip() for technique in value.split(",") if technique.strip()]


def _technique_names(value, count):
    separator = " -> " if " -> " in value else ","
    names = [name.strip() for name in value.split(separator)]
    return names if len(names) == count else [value] * count


def lookup_all(rule_name):
    """Return individual ATT&CK IDs and names for a rule."""
    value = ATTACK.get(rule_name)
    if not value:
        return []
    ids = _technique_ids(value[0])
    names = _technique_names(value[1], len(ids))
    return [{"id": technique_id, "name": name} for technique_id, name in zip(ids, names)]


def metadata(rule_name):
    """Return complete static ATT&CK metadata for a rule."""
    value = ATTACK.get(rule_name)
    if not value:
        return {}
    technique_id, technique_name = value
    techniques = lookup_all(rule_name)
    tactic_names = []
    for technique in techniques:
        for tactic in TECHNIQUE_TACTICS.get(technique["id"], ()):
            if tactic not in tactic_names:
                tactic_names.append(tactic)
    return {
        "rule_name": rule_name,
        "mitre": technique_id,
        "mitre_technique": technique_id,
        "technique_name": technique_name,
        "tactics": tactic_names,
        "techniques": [technique["id"] for technique in techniques],
    }


def lookup(rule_name):
    """Return ``(technique_id, technique_name)`` for a rule, if known."""
    value = ATTACK.get(rule_name)
    return ({"mitre_technique": value[0], "technique_name": value[1]}
            if value else {})
