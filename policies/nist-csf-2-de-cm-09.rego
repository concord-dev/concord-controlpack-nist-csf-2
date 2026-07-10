package concord.nist_csf_2.de_cm_09

import rego.v1

# NIST CSF 2.0 DE.CM-09 — computing hardware and software, runtime environments,
# and their utilization are monitored to find potentially adverse events.
# Concord verifies that in every active AWS region GuardDuty has an enabled
# detector (runtime threat monitoring over VPC, DNS, and CloudTrail telemetry)
# and AWS Config has a configuration recorder that is recording (hardware and
# software configuration monitoring). Reuses the GuardDuty per-region coverage
# logic from FedRAMP SI-3/SI-4. Fails closed when no evidence is collected or
# when no active region is reported, so absence of monitoring is never read as
# compliance.

deny contains msg if {
    not input.endpoint_monitoring
    msg := "DE.CM-09: no hardware/software monitoring evidence collected"
}

deny contains msg if {
    input.endpoint_monitoring
    count(input.endpoint_monitoring.active_regions) == 0
    msg := "DE.CM-09: no active regions reported; monitoring coverage cannot be verified — failing closed"
}

deny contains msg if {
    some region in input.endpoint_monitoring.active_regions
    not has_guardduty(region)
    msg := sprintf("DE.CM-09: GuardDuty runtime monitoring is not enabled in active region %q", [region])
}

deny contains msg if {
    some region in input.endpoint_monitoring.active_regions
    not has_config_recorder(region)
    msg := sprintf("DE.CM-09: AWS Config is not recording hardware/software configuration in active region %q", [region])
}

has_guardduty(region) if {
    some d in input.endpoint_monitoring.guardduty_detectors
    d.region == region
    d.status == "ENABLED"
}

has_config_recorder(region) if {
    some r in input.endpoint_monitoring.config_recorders
    r.region == region
    r.recording == true
}
