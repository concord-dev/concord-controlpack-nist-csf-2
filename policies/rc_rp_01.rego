package concord.nist_csf_2.rc_rp_01

import rego.v1

max_test_age_days := 90

deny contains msg if {
    not input.restore_tests
    msg := "no restore-test evidence collected"
}

deny contains msg if {
    count(input.restore_tests.tests) == 0
    msg := "no restore tests on record"
}

deny contains msg if {
    every test in input.restore_tests.tests {
        test.age_days > max_test_age_days
    }
    msg := sprintf("most recent restore test is older than %d days", [max_test_age_days])
}

deny contains msg if {
    every test in input.restore_tests.tests {
        test.status != "succeeded"
    }
    msg := "no restore test has ever succeeded"
}
