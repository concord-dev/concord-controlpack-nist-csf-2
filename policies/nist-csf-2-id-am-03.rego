package concord.nist_csf_2.nist_csf_2_id_am_03

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "nist_csf_2_id_am_03")
	msg := "NIST-CSF-2-ID.AM-03: aws evidence missing"
}

deny contains msg if {
	some r in input.nist_csf_2_id_am_03.resources
	not r.compliant
	msg := sprintf("NIST-CSF-2-ID.AM-03: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
