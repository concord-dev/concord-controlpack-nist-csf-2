package concord.nist_csf_2.rc_rp_03

import rego.v1

# NIST CSF 2.0 RC.RP-03: the integrity of backups and other restoration assets
# is verified before use. Evidence is collected via the aws backup_status
# collector. Concord fails closed when any recovery point has not had its
# integrity verified, when its last integrity check did not pass, or when that
# check has gone stale.

max_check_age_days := 30

deny contains msg if {
    not input.backups
    msg := "no backup-integrity evidence collected"
}

deny contains msg if {
    count(input.backups.recovery_points) == 0
    msg := "no backup recovery points on record"
}

deny contains msg if {
    some rp in input.backups.recovery_points
    not rp.integrity_verified
    msg := sprintf("backup recovery point %q has not had its integrity verified", [rp.id])
}

deny contains msg if {
    some rp in input.backups.recovery_points
    rp.last_integrity_check_status != "passed"
    msg := sprintf("backup recovery point %q failed its last integrity check (status=%q)", [rp.id, rp.last_integrity_check_status])
}

deny contains msg if {
    some rp in input.backups.recovery_points
    rp.integrity_check_age_days > max_check_age_days
    msg := sprintf("backup recovery point %q was last integrity-checked %d days ago (max %d)", [rp.id, rp.integrity_check_age_days, max_check_age_days])
}
