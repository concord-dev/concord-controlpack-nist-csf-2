package concord.nist_csf_2.nist_csf_2_rc_rp_06

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "nist_csf_2_rc_rp_06")
	msg := "NIST-CSF-2-RC.RP-06: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.nist_csf_2_rc_rp_06)
	msg := sprintf("NIST-CSF-2-RC.RP-06: attestation expired (expires_at=%s)", [input.nist_csf_2_rc_rp_06.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.nist_csf_2_rc_rp_06, 365)
	msg := sprintf("NIST-CSF-2-RC.RP-06: attestation not reviewed in 365 days (last_review_at=%s)", [input.nist_csf_2_rc_rp_06.last_review_at])
}
