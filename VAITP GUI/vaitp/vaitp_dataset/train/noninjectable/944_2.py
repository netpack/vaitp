# 3.11 (2023-04-28)

## New Features

## Minor Updates

- Requirements have been updated for 3.11

## New Bugs

- Python_TA reports are not currently provided since the configuration file provides cannot be parsed by the newest version of Python_TA.


# 3.10 (2022-10-21)

## New Features

- Added SQAM partial marking (string similarity checker) in problems_rdb, and a flag for it -- SQAM_USED - in settings_pcrs.py. This will allow adding datasets for SQL problems that mark using SQAM. By default, binary marking (what PCRS usually uses) is used when running test cases. For more info see: https://github.com/ShahmeerShahid/sqam
- Added support for Parsons's problems in Python. Add "'problems_parsons': ''" to INSTALLED_PROBLEM_APPS to enable.
- Added initial support for RISCV assembly problems. Add "'problems_riscv': 'RiscV'" to INSTALLED_PROBLEM_APPS to enable. See doc/guides for information on how to install dependencies required for RISCV and to learn how to write tests.

## Minor Updates

- Removed PyTA check for E9972 (type hint for class attribute)

# 3.9 (2021-11-24)

## New Features

- Enhanced Python testing capability: Added _pcrs variables that can be accessed by the test code that contain the student's script and STDOUT.
- Added time on page tracking capability: Javascript indicates whenever a PCRS challenge page is in focus, allowing rough calculations of time spent on a PCRS page.

## Bug Fixes

- Removed a number of errors related to a student's shibboleth authentication timing out before a new request is made.
- Standardized time reported in logs.
- Switched psycopg string format to utf-8 to match postgres.
