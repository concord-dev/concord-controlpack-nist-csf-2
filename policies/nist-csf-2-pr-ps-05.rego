package concord.nist_csf_2.pr_ps_05

import rego.v1

# NIST CSF 2.0 PR.PS-05 — Installation and execution of unauthorized software
# is prevented. Concord reads a signed attestation for the software
# allowlisting program and fails if it is missing, unsigned, of the wrong
# kind, or omits the allowlisting method/technology, the enforcement points it
# covers, the exception process for approving new software, or the review
# date.

deny contains msg if {
	not input.attestation
	msg := "no software-allowlisting attestation collected"
}

deny contains msg if {
	input.attestation.kind != "software_allowlisting"
	msg := sprintf("attestation kind is %q, expected \"software_allowlisting\"", [input.attestation.kind])
}

deny contains msg if {
	not input.attestation.signature_verified
	msg := "software-allowlisting attestation signature did not verify"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "allowlisting_method", "") == ""
	msg := "attestation does not document an allowlisting method/technology"
}

deny contains msg if {
	count(object.get(input.attestation.attested_fields, "enforcement_points", [])) == 0
	msg := "attestation names no enforcement points where allowlisting is applied (e.g. endpoints, servers, CI runners)"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "exception_process", "") == ""
	msg := "attestation does not document an exception process for authorizing new software"
}

deny contains msg if {
	object.get(input.attestation.attested_fields, "last_reviewed_at", "") == ""
	msg := "attestation records no last_reviewed_at date"
}
