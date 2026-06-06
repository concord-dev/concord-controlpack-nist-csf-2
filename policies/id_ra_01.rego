package concord.nist_csf_2.id_ra_01

import rego.v1

max_scan_staleness_days := 7

deny contains msg if {
    not input.vuln_scan
    msg := "no vulnerability-scan evidence collected"
}

deny contains msg if {
    input.vuln_scan.scan_age_days > max_scan_staleness_days
    msg := sprintf("most recent scan was %d days ago (max %d)", [input.vuln_scan.scan_age_days, max_scan_staleness_days])
}

deny contains msg if {
    some issue in input.vuln_scan.issues
    issue.status == "open"
    not issue.validated
    msg := sprintf("issue %q is open but has not been validated", [issue.id])
}
