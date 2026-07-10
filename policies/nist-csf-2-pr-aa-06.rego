package concord.nist_csf_2.pr_aa_06

import rego.v1

# NIST CSF 2.0 PR.AA-06 — Physical access to assets is managed, monitored, and
# enforced commensurate with risk. Concord reads a signed attestation covering
# the facilities that hold in-scope assets and fails if it is missing,
# unsigned, of the wrong kind, or omits the physical access-control measures
# in place, the roles authorized for entry, whether physical access is logged,
# or the last review date.

deny contains msg if {
	not input.attestation
	msg := "no physical-access attestation collected"
}

deny contains msg if {
	input.attestation.kind != "physical_access"
	msg := sprintf("attestation kind is %q, expected \"physical_access\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "physical-access attestation signature did not verify"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "access_control_measures", [])) == 0
	msg := "attestation names no physical access-control measures (e.g. badge readers, mantrap, biometrics)"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "authorized_roles", [])) == 0
	msg := "attestation does not enumerate the roles authorized for physical entry"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "access_logging", false) != true
	msg := "attestation does not confirm that physical access is logged"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
