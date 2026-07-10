package concord.nist_csf_2.pr_ps_01

import rego.v1

# NIST CSF 2.0 PR.PS-01 — configuration management practices are established
# and applied. Implemented via NIST 800-53 CM-2 (Baseline Configuration): the
# AWS Config recorder must be enabled and recording in every active region so
# the configuration of all resources is continuously captured. Evidence: AWS
# Config recorder status (input.config_recorders). Adapted from
# concord.fedramp.cm_2_baseline. Fail-closed: absent evidence, no active
# regions, or a non-recording region denies.

deny contains msg if {
	not input.config_recorders
	msg := "NIST CSF 2.0 PR.PS-01: no AWS Config recorder evidence collected — cannot demonstrate established configuration management (NIST 800-53 CM-2)"
}

deny contains msg if {
	input.config_recorders
	count(object.get(input.config_recorders, "active_regions", [])) == 0
	msg := "NIST CSF 2.0 PR.PS-01: no active regions reported — cannot demonstrate configuration recording coverage (NIST 800-53 CM-2)"
}

deny contains msg if {
	some region in input.config_recorders.active_regions
	not has_recording_in_region(region)
	msg := sprintf("NIST CSF 2.0 PR.PS-01: AWS Config recorder is not recording in active region %q — configuration is not captured there (NIST 800-53 CM-2)", [region])
}

has_recording_in_region(region) if {
	some recorder in input.config_recorders.recorders
	recorder.region == region
	recorder.recording == true
}
