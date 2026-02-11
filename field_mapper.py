EVENT_ID_TO_TYPE = {
    4688: "process_creation",
    4624: "successful_login",
    4625: "failed_login",
    4672: "privileged_logon",
    1102: "log_cleared",
    4719: "audit_policy_change"
}

SEVERITY_BY_EVENT = {
    "process_creation": "medium",
    "failed_login": "low",
    "privileged_logon": "high",
    "log_cleared": "high",
    "audit_policy_change": "high"
}
