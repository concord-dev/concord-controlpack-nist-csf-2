package concord.nist_csf_2.de_ae_03

import rego.v1

deny contains msg if {
    not input.cloudtrail
    msg := "no CloudTrail evidence collected"
}

deny contains msg if {
    not has_multi_region_trail
    msg := "no multi-region CloudTrail trail is logging"
}

has_multi_region_trail if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
}
