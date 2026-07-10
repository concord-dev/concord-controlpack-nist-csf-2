package concord.nist_csf_2.id_am_03

import rego.v1

# NIST CSF 2.0 ID.AM-03 — authorised hardware/cloud assets are inventoried.
# Cloud-native reading of "hardware": the AWS Config recorder is the
# authoritative resource inventory, and every compute instance must carry
# the ownership tags that make it a tracked, accountable asset.

required_tags := {"owner", "environment", "data_classification"}

deny contains msg if {
    not input.ec2_inventory
    msg := "no hardware/cloud asset inventory evidence collected"
}

deny contains msg if {
    not input.ec2_inventory.config_recorder_active
    msg := "AWS Config recorder is not active — authoritative asset inventory is missing"
}

deny contains msg if {
    some instance in input.ec2_inventory.instances
    some required in required_tags
    not instance.tags[required]
    msg := sprintf("asset %q is missing required inventory tag %q", [instance.id, required])
}
