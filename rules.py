RULES = [
    {
        "id": "BRUTE_FORCE_LOGIN",
        "keyword": "failed login",
        "severity": "high",
        "description": "Possible brute-force login attempts detected.",
    },
    {
        "id": "PORT_SCAN",
        "keyword": "port scan",
        "severity": "medium",
        "description": "Potential port scan or reconnaissance activity.",
    },
    {
        "id": "PRIV_ESC",
        "keyword": "privilege escalation",
        "severity": "high",
        "description": "Privilege escalation attempt detected.",
    },
    {
        "id": "SUSPICIOUS_PROCESS",
        "keyword": "suspicious process",
        "severity": "medium",
        "description": "Suspicious process execution detected.",
    },
    {
        "id": "CREDENTIAL_COMPROMISE",
        "keyword": "credential compromise",
        "severity": "high",
        "description": "Possible credential compromise.",
    },
]
