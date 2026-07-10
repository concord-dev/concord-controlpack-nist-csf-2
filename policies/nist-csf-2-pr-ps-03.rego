package concord.nist_csf_2.pr_ps_03

import rego.v1

# NIST CSF 2.0 PR.PS-03 — Hardware is managed throughout its lifecycle
# (maintenance, replacement, and secure removal) commensurate with risk.
# Concord reads a signed attestation for the hardware lifecycle program and
# fails if it is missing, unsigned, of the wrong kind, or omits the
# maintenance process, the replacement criteria, confirmation that
# decommissioned hardware is securely sanitized/disposed, or the review date.

deny contains msg if {
	not input.attestation
	msg := "no hardware-lifecycle attestation collected"
}

deny contains msg if {
	input.attestation.kind != "hardware_lifecycle"
	msg := sprintf("attestation kind is %q, expected \"hardware_lifecycle\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "hardware-lifecycle attestation signature did not verify"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "maintenance_process", "") == ""
	msg := "attestation does not document a hardware maintenance process"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "replacement_criteria", "") == ""
	msg := "attestation does not document hardware replacement criteria"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "secure_disposal", false) != true
	msg := "attestation does not confirm secure sanitization/disposal of retired hardware"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
