package concord.nist_csf_2.de_cm_03

import rego.v1

# NIST CSF 2.0 DE.CM-03 — personnel activity and technology usage are monitored
# to find potentially adverse events. Concord verifies that AWS CloudTrail
# records personnel (user) activity across every region via a multi-region
# trail, and that the trail logs management (control-plane) events for both read
# and write actions plus at least one data-event selector, so that both
# privileged user actions and data-plane technology usage are captured. Reuses
# the multi-region-trail check from the in-pack DE.AE-03 policy and the
# event-selector logic from FedRAMP AU-2. Fails closed when no evidence exists.

trails := input.cloudtrail.trails

deny contains msg if {
    not input.cloudtrail
    msg := "DE.CM-03: no CloudTrail evidence collected"
}

deny contains msg if {
    input.cloudtrail
    not has_multi_region_trail
    msg := "DE.CM-03: no multi-region CloudTrail trail is logging; personnel activity is not monitored across all regions"
}

deny contains msg if {
    input.cloudtrail
    not mgmt_read_logged
    msg := "DE.CM-03: CloudTrail is not logging management read events; privileged personnel read activity is not captured"
}

deny contains msg if {
    input.cloudtrail
    not mgmt_write_logged
    msg := "DE.CM-03: CloudTrail is not logging management write events; personnel change activity is not captured"
}

deny contains msg if {
    input.cloudtrail
    not data_events_logged
    msg := "DE.CM-03: CloudTrail has no data-event selector; technology usage (data-plane access) is not captured"
}

has_multi_region_trail if {
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

data_events_logged if {
    some trail in trails
    some sel in trail.event_selectors
    count(sel.data_resources) > 0
}
