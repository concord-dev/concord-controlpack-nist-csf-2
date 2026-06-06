package concord.nist_csf_2.gv_rr_02

import rego.v1

required_functions := {
    "incident_response",
    "access_management",
    "vulnerability_management",
    "vendor_risk_management",
    "data_protection",
}

deny contains msg if {
    not input.attestation
    msg := "no RACI attestation collected"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "RACI attestation cosign signature did not verify"
}

deny contains msg if {
    some required in required_functions
    not has_function(required)
    msg := sprintf("RACI is missing function %q", [required])
}

deny contains msg if {
    some entry in input.attestation.attested_fields.functions
    not entry.accountable
    msg := sprintf("function %q has no accountable owner assigned", [entry.id])
}

has_function(id) if {
    some entry in input.attestation.attested_fields.functions
    entry.id == id
}
