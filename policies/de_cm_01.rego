package concord.nist_csf_2.de_cm_01

import rego.v1

deny contains msg if {
    not input.vpc_flow_logs
    msg := "no VPC flow-logs evidence collected"
}

deny contains msg if {
    some vpc in input.vpc_flow_logs.vpcs
    not vpc.flow_logs_enabled
    msg := sprintf("VPC %q in region %q has flow logs disabled", [vpc.id, vpc.region])
}
