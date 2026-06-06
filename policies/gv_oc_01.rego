package concord.nist_csf_2.gv_oc_01

import rego.v1

required_fields := {"mission_statement", "primary_stakeholders", "risk_appetite"}

deny contains msg if {
    not input.attestation
    msg := "no org-mission attestation collected"
}

deny contains msg if {
    input.attestation.kind != "org_mission_context"
    msg := sprintf("attestation kind is %q, expected \"org_mission_context\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("attestation missing required field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "mission attestation cosign signature did not verify"
}
