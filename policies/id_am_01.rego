package concord.nist_csf_2.id_am_01

import rego.v1

required_tags := {"owner", "environment", "data_classification"}

deny contains msg if {
    not input.ec2_inventory
    msg := "no EC2 inventory evidence collected"
}

deny contains msg if {
    not input.ec2_inventory.config_recorder_active
    msg := "AWS Config recorder is not active — authoritative inventory missing"
}

deny contains msg if {
    some instance in input.ec2_inventory.instances
    some required in required_tags
    not instance.tags[required]
    msg := sprintf("EC2 instance %q is missing required tag %q", [instance.id, required])
}
