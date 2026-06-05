package concord.nist_csf_2.gv_rm_01

import rego.v1

# NIST CSF 2.0 GV.RM-01 — risk-management strategy established and agreed.

required_fields := {"objectives", "stakeholders", "review_cadence_days"}

deny contains msg if {
    not input.attestation
    msg := "no risk-management-strategy attestation collected"
}

deny contains msg if {
    input.attestation.kind != "risk_management_strategy"
    msg := sprintf("attestation kind is %q, expected \"risk_management_strategy\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("strategy missing required field: %s", [f])
}

deny contains msg if {
    count(input.attestation.attested_fields.objectives) == 0
    msg := "strategy lists zero objectives"
}

deny contains msg if {
    count(input.attestation.attested_fields.stakeholders) == 0
    msg := "strategy has no stakeholders agreeing to the objectives"
}
