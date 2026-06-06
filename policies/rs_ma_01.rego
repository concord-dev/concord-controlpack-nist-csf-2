package concord.nist_csf_2.rs_ma_01

import rego.v1

max_tabletop_age_days := 365

required_fields := {"version", "owner", "last_tabletop_at",
                    "rto_hours", "rpo_hours"}

deny contains msg if {
    not input.attestation
    msg := "no incident-response-plan attestation collected"
}

deny contains msg if {
    input.attestation.kind != "incident_response_plan"
    msg := sprintf("attestation kind is %q, expected \"incident_response_plan\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "IRP attestation cosign signature did not verify"
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("IRP missing field: %s", [f])
}

deny contains msg if {
    input.attestation.attested_fields.tabletop_age_days > max_tabletop_age_days
    msg := sprintf("last tabletop exercise was %d days ago (max %d)", [input.attestation.attested_fields.tabletop_age_days, max_tabletop_age_days])
}
