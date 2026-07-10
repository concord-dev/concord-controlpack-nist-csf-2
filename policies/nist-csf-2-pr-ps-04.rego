package concord.nist_csf_2.pr_ps_04

import rego.v1

# NIST CSF 2.0 PR.PS-04 — log records are generated and made available for
# continuous monitoring. Implemented via NIST 800-53 AU-2 (Event Logging) and
# AU-12 (Audit Record Generation): AWS CloudTrail must run at least one
# multi-region trail that is actively logging, and its event selectors must
# capture management (control-plane) read and write events. Evidence:
# input.cloudtrail_events.trails. Adapted from concord.fedramp.au_2,
# concord.fedramp.au_12, and concord.nist_csf_2.de_ae_03. Each missing category
# denies independently; fail-closed when no evidence is present.

trails := input.cloudtrail_events.trails

deny contains msg if {
	not input.cloudtrail_events
	msg := "NIST CSF 2.0 PR.PS-04: no CloudTrail evidence collected"
}

deny contains msg if {
	input.cloudtrail_events
	not has_multi_region_logging_trail
	msg := "NIST CSF 2.0 PR.PS-04: no multi-region CloudTrail trail is both enabled and logging; log records are not generated across every region (NIST 800-53 AU-12)"
}

deny contains msg if {
	input.cloudtrail_events
	not mgmt_read_logged
	msg := "NIST CSF 2.0 PR.PS-04: CloudTrail is not logging management (control-plane) read events; privileged read activity is not captured for monitoring (NIST 800-53 AU-2)"
}

deny contains msg if {
	input.cloudtrail_events
	not mgmt_write_logged
	msg := "NIST CSF 2.0 PR.PS-04: CloudTrail is not logging management (control-plane) write events; privileged change activity is not captured for monitoring (NIST 800-53 AU-2)"
}

has_multi_region_logging_trail if {
	some trail in trails
	trail.is_multi_region_trail
	trail.is_logging
}

mgmt_read_logged if {
	some trail in trails
	some sel in trail.event_selectors
	sel.include_management_events == true
	sel.read_write_type in {"All", "ReadOnly"}
}

mgmt_write_logged if {
	some trail in trails
	some sel in trail.event_selectors
	sel.include_management_events == true
	sel.read_write_type in {"All", "WriteOnly"}
}
