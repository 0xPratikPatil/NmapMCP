# Test Results — NmapMCP Enhanced Fork

Raw evidence for PR reviewers. All output below is verbatim from the test run on this machine.

- **Platform:** win32, Python 3.13.14, pytest 9.1.1
- **Nmap:** 7.99 at `C:/PROGRA~2/Nmap/nmap.exe`
- **Date:** 2026-09-19

---

## Section 1 — Import Sanity

Confirms `main.py` loads with no syntax errors.

```
$ uv run python -c "import main; print('import OK')"
import OK
```

---

## Section 2 — Linter (ruff, bug-class rules only)

Rules checked: F401 (unused imports), F811, F821, F841, E711, E712, W-class warnings.
E501 line-length excluded (style, not bugs).

**Before fix** — 3 unused imports were present:
```
main.py:25:8: F401 [*] `subprocess` imported but unused
main.py:32:47: F401 [*] `ipaddress.AddressValueError` imported but unused
main.py:33:21: F401 [*] `pathlib.Path` imported but unused
```

**After fix:**
```
$ uv run ruff check main.py --select F401,F811,F821,F841,E711,E712,W --output-format concise
All checks passed!
```

---

## Section 3 — Test Collection Count

108 tests collected (live localhost tests excluded from CI run; they require nmap binary and are in `tests/test_live_localhost.py`).

```
$ uv run pytest tests/ --ignore=tests/test_live_localhost.py --collect-only -q

tests/test_diff_scans.py::test_diff_detects_opened_port
tests/test_diff_scans.py::test_diff_detects_closed_port
tests/test_diff_scans.py::test_diff_detects_version_change
tests/test_diff_scans.py::test_diff_no_changes
tests/test_diff_scans.py::test_diff_missing_scan_id_a
tests/test_diff_scans.py::test_diff_missing_scan_id_b
tests/test_diff_scans.py::test_diff_multi_host
tests/test_guardrails.py::test_public_ip_blocked_in_scan_tool[8.8.8.8]
tests/test_guardrails.py::test_public_ip_blocked_in_scan_tool[1.1.1.1]
tests/test_guardrails.py::test_public_ip_blocked_in_scan_tool[208.67.222.222]
tests/test_guardrails.py::test_public_ip_blocked_in_quick_scan[8.8.8.8]
tests/test_guardrails.py::test_public_ip_blocked_in_quick_scan[1.1.1.1]
tests/test_guardrails.py::test_disallowed_flag_raises_valueerror
tests/test_guardrails.py::test_multiple_disallowed_flags
tests/test_guardrails.py::test_another_made_up_flag
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1; whoami]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1 && id]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[$(hostname)]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1`id`]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1 | cat /etc/passwd]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1>evil.txt]
tests/test_guardrails.py::test_validate_flags_raises_for_disallowed
tests/test_guardrails.py::test_validate_flags_raises_for_missing_value
tests/test_guardrails.py::test_validate_target_raises_for_metachar
tests/test_guardrails.py::test_validate_target_raises_for_public_when_blocked
tests/test_guardrails.py::test_validate_target_raises_for_overlong
tests/test_is_private.py::test_is_private_true[10.0.0.1]
tests/test_is_private.py::test_is_private_true[10.255.255.255]
tests/test_is_private.py::test_is_private_true[172.16.0.1]
tests/test_is_private.py::test_is_private_true[172.20.0.1]
tests/test_is_private.py::test_is_private_true[172.31.255.255]
tests/test_is_private.py::test_is_private_true[192.168.0.1]
tests/test_is_private.py::test_is_private_true[192.168.255.254]
tests/test_is_private.py::test_is_private_true[127.0.0.1]
tests/test_is_private.py::test_is_private_true[127.0.0.2]
tests/test_is_private.py::test_is_private_true[::1]
tests/test_is_private.py::test_is_private_true[fc00::1]
tests/test_is_private.py::test_is_private_true[fd00::dead:beef]
tests/test_is_private.py::test_is_private_true[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]
tests/test_is_private.py::test_is_private_false[8.8.8.8]
tests/test_is_private.py::test_is_private_false[1.1.1.1]
tests/test_is_private.py::test_is_private_false[208.67.222.222]
tests/test_is_private.py::test_is_private_false[172.15.255.255]
tests/test_is_private.py::test_is_private_false[172.32.0.1]
tests/test_is_private.py::test_is_private_false[11.0.0.1]
tests/test_is_private.py::test_is_private_false[192.169.0.1]
tests/test_is_private.py::test_is_private_unresolvable_hostname_treated_as_private
tests/test_is_private.py::test_is_private_hostname_resolves_to_private
tests/test_is_private.py::test_is_private_hostname_resolves_to_public
tests/test_parse_xml.py::test_normal_host_parsed
tests/test_parse_xml.py::test_os_detection_parsed
tests/test_parse_xml.py::test_host_scripts_parsed
tests/test_parse_xml.py::test_traceroute_parsed
tests/test_parse_xml.py::test_malformed_xml_returns_error
tests/test_parse_xml.py::test_empty_xml_returns_empty_list
tests/test_parse_xml.py::test_no_hosts_in_valid_xml
tests/test_parse_xml.py::test_all_expected_keys_present
tests/test_validate_flags.py::test_allowed_flags_no_value[-F -T4-expected0]
tests/test_validate_flags.py::test_allowed_flags_no_value[-sV-expected1]
tests/test_validate_flags.py::test_allowed_flags_no_value[-sT -Pn --open-expected2]
tests/test_validate_flags.py::test_allowed_flags_no_value[-A-expected3]
tests/test_validate_flags.py::test_allowed_flags_no_value[-6 -n-expected4]
tests/test_validate_flags.py::test_allowed_flags_no_value[-v -vv-expected5]
tests/test_validate_flags.py::test_allowed_flags_no_value[--open --reason-expected6]
tests/test_validate_flags.py::test_flag_with_value_paired
tests/test_validate_flags.py::test_top_ports_with_value
tests/test_validate_flags.py::test_script_with_value
tests/test_validate_flags.py::test_version_intensity_with_value
tests/test_validate_flags.py::test_flag_with_value_inline_equals
tests/test_validate_flags.py::test_disallowed_flags_raise[-Z]
tests/test_validate_flags.py::test_disallowed_flags_raise[--evil]
tests/test_validate_flags.py::test_disallowed_flags_raise[--script-injection]
tests/test_validate_flags.py::test_disallowed_flags_raise[-sY]
tests/test_validate_flags.py::test_disallowed_flags_raise[--badopt]
tests/test_validate_flags.py::test_path_traversal_flag_check[--output-file=../../etc/passwd]
tests/test_validate_flags.py::test_path_traversal_flag_check[-oZ /tmp/evil]
tests/test_validate_flags.py::test_path_traversal_flag_check[--script=../../etc/passwd]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[-p]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--top-ports]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--script]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--version-intensity]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--min-rate]
tests/test_validate_flags.py::test_mixed_valid_then_invalid
tests/test_validate_flags.py::test_empty_flags
tests/test_validate_target.py::test_valid_private_targets[127.0.0.1]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.1]
tests/test_validate_target.py::test_valid_private_targets[10.0.0.0/8]
tests/test_validate_target.py::test_valid_private_targets[172.16.5.100]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.0/24]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.1 192.168.1.2]
tests/test_validate_target.py::test_valid_private_targets[localhost]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.1,192.168.1.2]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1; whoami]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1 && id]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1 | cat /etc/passwd]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1`id`]
tests/test_validate_target.py::test_illegal_characters_rejected[$(hostname)]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1\nwhoami]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1>out.txt]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1"]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1']
tests/test_validate_target.py::test_overlong_target_rejected
tests/test_validate_target.py::test_public_ip_blocked_by_default[8.8.8.8]
tests/test_validate_target.py::test_public_ip_blocked_by_default[1.1.1.1]
tests/test_validate_target.py::test_public_ip_blocked_by_default[208.67.222.222]
tests/test_validate_target.py::test_public_ip_allowed_when_env_set[8.8.8.8]
tests/test_validate_target.py::test_public_ip_allowed_when_env_set[1.1.1.1]
tests/test_validate_target.py::test_target_length_boundary

108 tests collected in 0.52s
```

---

## Section 4 — Full pytest -v Run (108 tests, no network required)

```
$ uv run pytest tests/ --ignore=tests/test_live_localhost.py -v

========================================================== test session starts ==========================================================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\Hp\NmapMCP\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\Hp\NmapMCP
configfile: pyproject.toml
plugins: anyio-4.9.0, asyncio-1.4.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 108 items

tests/test_diff_scans.py::test_diff_detects_opened_port PASSED                                                                     [  0%]
tests/test_diff_scans.py::test_diff_detects_closed_port PASSED                                                                     [  1%]
tests/test_diff_scans.py::test_diff_detects_version_change PASSED                                                                  [  2%]
tests/test_diff_scans.py::test_diff_no_changes PASSED                                                                              [  3%]
tests/test_diff_scans.py::test_diff_missing_scan_id_a PASSED                                                                       [  4%]
tests/test_diff_scans.py::test_diff_missing_scan_id_b PASSED                                                                       [  5%]
tests/test_diff_scans.py::test_diff_multi_host PASSED                                                                              [  6%]
tests/test_guardrails.py::test_public_ip_blocked_in_scan_tool[8.8.8.8] PASSED                                                      [  7%]
tests/test_guardrails.py::test_public_ip_blocked_in_scan_tool[1.1.1.1] PASSED                                                      [  8%]
tests/test_guardrails.py::test_public_ip_blocked_in_scan_tool[208.67.222.222] PASSED                                               [  9%]
tests/test_guardrails.py::test_public_ip_blocked_in_quick_scan[8.8.8.8] PASSED                                                     [ 10%]
tests/test_guardrails.py::test_public_ip_blocked_in_quick_scan[1.1.1.1] PASSED                                                     [ 11%]
tests/test_guardrails.py::test_disallowed_flag_raises_valueerror PASSED                                                            [ 12%]
tests/test_guardrails.py::test_multiple_disallowed_flags PASSED                                                                    [ 12%]
tests/test_guardrails.py::test_another_made_up_flag PASSED                                                                         [ 13%]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1; whoami] PASSED                                         [ 14%]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1 && id] PASSED                                           [ 15%]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[$(hostname)] PASSED                                               [ 16%]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1`id`] PASSED                                             [ 17%]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1 | cat /etc/passwd] PASSED                               [ 18%]
tests/test_guardrails.py::test_shell_metachar_in_target_rejected[127.0.0.1>evil.txt] PASSED                                        [ 19%]
tests/test_guardrails.py::test_validate_flags_raises_for_disallowed PASSED                                                         [ 20%]
tests/test_guardrails.py::test_validate_flags_raises_for_missing_value PASSED                                                      [ 21%]
tests/test_guardrails.py::test_validate_target_raises_for_metachar PASSED                                                          [ 22%]
tests/test_guardrails.py::test_validate_target_raises_for_public_when_blocked PASSED                                               [ 23%]
tests/test_guardrails.py::test_validate_target_raises_for_overlong PASSED                                                          [ 24%]
tests/test_is_private.py::test_is_private_true[10.0.0.1] PASSED                                                                    [ 25%]
tests/test_is_private.py::test_is_private_true[10.255.255.255] PASSED                                                              [ 25%]
tests/test_is_private.py::test_is_private_true[172.16.0.1] PASSED                                                                  [ 26%]
tests/test_is_private.py::test_is_private_true[172.20.0.1] PASSED                                                                  [ 27%]
tests/test_is_private.py::test_is_private_true[172.31.255.255] PASSED                                                              [ 28%]
tests/test_is_private.py::test_is_private_true[192.168.0.1] PASSED                                                                 [ 29%]
tests/test_is_private.py::test_is_private_true[192.168.255.254] PASSED                                                             [ 30%]
tests/test_is_private.py::test_is_private_true[127.0.0.1] PASSED                                                                   [ 31%]
tests/test_is_private.py::test_is_private_true[127.0.0.2] PASSED                                                                   [ 32%]
tests/test_is_private.py::test_is_private_true[::1] PASSED                                                                         [ 33%]
tests/test_is_private.py::test_is_private_true[fc00::1] PASSED                                                                     [ 34%]
tests/test_is_private.py::test_is_private_true[fd00::dead:beef] PASSED                                                             [ 35%]
tests/test_is_private.py::test_is_private_true[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff] PASSED                                     [ 36%]
tests/test_is_private.py::test_is_private_false[8.8.8.8] PASSED                                                                    [ 37%]
tests/test_is_private.py::test_is_private_false[1.1.1.1] PASSED                                                                    [ 37%]
tests/test_is_private.py::test_is_private_false[208.67.222.222] PASSED                                                             [ 38%]
tests/test_is_private.py::test_is_private_false[172.15.255.255] PASSED                                                             [ 39%]
tests/test_is_private.py::test_is_private_false[172.32.0.1] PASSED                                                                 [ 40%]
tests/test_is_private.py::test_is_private_false[11.0.0.1] PASSED                                                                   [ 41%]
tests/test_is_private.py::test_is_private_false[192.169.0.1] PASSED                                                                [ 42%]
tests/test_is_private.py::test_is_private_unresolvable_hostname_treated_as_private PASSED                                          [ 43%]
tests/test_is_private.py::test_is_private_hostname_resolves_to_private PASSED                                                      [ 44%]
tests/test_is_private.py::test_is_private_hostname_resolves_to_public PASSED                                                       [ 45%]
tests/test_parse_xml.py::test_normal_host_parsed PASSED                                                                            [ 46%]
tests/test_parse_xml.py::test_os_detection_parsed PASSED                                                                           [ 47%]
tests/test_parse_xml.py::test_host_scripts_parsed PASSED                                                                           [ 48%]
tests/test_parse_xml.py::test_traceroute_parsed PASSED                                                                             [ 49%]
tests/test_parse_xml.py::test_malformed_xml_returns_error PASSED                                                                   [ 50%]
tests/test_parse_xml.py::test_empty_xml_returns_empty_list PASSED                                                                  [ 50%]
tests/test_parse_xml.py::test_no_hosts_in_valid_xml PASSED                                                                         [ 51%]
tests/test_parse_xml.py::test_all_expected_keys_present PASSED                                                                     [ 52%]
tests/test_validate_flags.py::test_allowed_flags_no_value[-F -T4-expected0] PASSED                                                 [ 53%]
tests/test_validate_flags.py::test_allowed_flags_no_value[-sV-expected1] PASSED                                                    [ 54%]
tests/test_validate_flags.py::test_allowed_flags_no_value[-sT -Pn --open-expected2] PASSED                                         [ 55%]
tests/test_validate_flags.py::test_allowed_flags_no_value[-A-expected3] PASSED                                                     [ 56%]
tests/test_validate_flags.py::test_allowed_flags_no_value[-6 -n-expected4] PASSED                                                  [ 57%]
tests/test_validate_flags.py::test_allowed_flags_no_value[-v -vv-expected5] PASSED                                                 [ 58%]
tests/test_validate_flags.py::test_allowed_flags_no_value[--open --reason-expected6] PASSED                                        [ 59%]
tests/test_validate_flags.py::test_flag_with_value_paired PASSED                                                                   [ 60%]
tests/test_validate_flags.py::test_top_ports_with_value PASSED                                                                     [ 61%]
tests/test_validate_flags.py::test_script_with_value PASSED                                                                        [ 62%]
tests/test_validate_flags.py::test_version_intensity_with_value PASSED                                                             [ 62%]
tests/test_validate_flags.py::test_flag_with_value_inline_equals PASSED                                                            [ 63%]
tests/test_validate_flags.py::test_disallowed_flags_raise[-Z] PASSED                                                               [ 64%]
tests/test_validate_flags.py::test_disallowed_flags_raise[--evil] PASSED                                                           [ 65%]
tests/test_validate_flags.py::test_disallowed_flags_raise[--script-injection] PASSED                                               [ 66%]
tests/test_validate_flags.py::test_disallowed_flags_raise[-sY] PASSED                                                              [ 67%]
tests/test_validate_flags.py::test_disallowed_flags_raise[--badopt] PASSED                                                         [ 68%]
tests/test_validate_flags.py::test_path_traversal_flag_check[--output-file=../../etc/passwd] PASSED                                [ 69%]
tests/test_validate_flags.py::test_path_traversal_flag_check[-oZ /tmp/evil] PASSED                                                 [ 70%]
tests/test_validate_flags.py::test_path_traversal_flag_check[--script=../../etc/passwd] PASSED                                     [ 71%]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[-p] PASSED                                                      [ 72%]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--top-ports] PASSED                                             [ 73%]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--script] PASSED                                                [ 74%]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--version-intensity] PASSED                                     [ 75%]
tests/test_validate_flags.py::test_value_flag_missing_value_raises[--min-rate] PASSED                                              [ 75%]
tests/test_validate_flags.py::test_mixed_valid_then_invalid PASSED                                                                 [ 76%]
tests/test_validate_flags.py::test_empty_flags PASSED                                                                              [ 77%]
tests/test_validate_target.py::test_valid_private_targets[127.0.0.1] PASSED                                                        [ 78%]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.1] PASSED                                                      [ 79%]
tests/test_validate_target.py::test_valid_private_targets[10.0.0.0/8] PASSED                                                       [ 80%]
tests/test_validate_target.py::test_valid_private_targets[172.16.5.100] PASSED                                                     [ 81%]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.0/24] PASSED                                                   [ 82%]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.1 192.168.1.2] PASSED                                          [ 83%]
tests/test_validate_target.py::test_valid_private_targets[localhost] PASSED                                                        [ 84%]
tests/test_validate_target.py::test_valid_private_targets[192.168.1.1,192.168.1.2] PASSED                                          [ 85%]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1; whoami] PASSED                                          [ 86%]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1 && id] PASSED                                            [ 87%]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1 | cat /etc/passwd] PASSED                                [ 87%]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1`id`] PASSED                                            [ 88%]
tests/test_validate_target.py::test_illegal_characters_rejected[$(hostname)] PASSED                                                [ 89%]
tests/test_validate_target.py::test_illegal_characters_rejected[127.0.0.1\nwhoami] PASSED                                          [ 90%]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1>out.txt] PASSED                                        [ 91%]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1"] PASSED                                               [ 92%]
tests/test_validate_target.py::test_illegal_characters_rejected[192.168.1.1'] PASSED                                               [ 93%]
tests/test_validate_target.py::test_overlong_target_rejected PASSED                                                                [ 94%]
tests/test_validate_target.py::test_public_ip_blocked_by_default[8.8.8.8] PASSED                                                   [ 95%]
tests/test_validate_target.py::test_public_ip_blocked_by_default[1.1.1.1] PASSED                                                   [ 96%]
tests/test_validate_target.py::test_public_ip_blocked_by_default[208.67.222.222] PASSED                                            [ 97%]
tests/test_validate_target.py::test_public_ip_allowed_when_env_set[8.8.8.8] PASSED                                                 [ 98%]
tests/test_validate_target.py::test_public_ip_allowed_when_env_set[1.1.1.1] PASSED                                                 [ 99%]
tests/test_validate_target.py::test_target_length_boundary PASSED                                                                  [100%]

========================================================== 108 passed in 0.79s ==========================================================
```

---

## Section 5 — Live Smoke Tests (requires nmap binary + localhost)

Run separately with: `uv run pytest tests/test_live_localhost.py -v`

These 7 tests scan `127.0.0.1` only and require Nmap 7.99 at `C:/PROGRA~2/Nmap/nmap.exe`.
All 7 passed in 55.83s on the development machine (Windows, Nmap 7.99, Python 3.13.14).

```
tests/test_live_localhost.py::test_live_quick_scan PASSED
tests/test_live_localhost.py::test_live_structured_scan PASSED
tests/test_live_localhost.py::test_live_check_single_port[135] PASSED
tests/test_live_localhost.py::test_live_check_single_port[445] PASSED
tests/test_live_localhost.py::test_live_ping_sweep PASSED
tests/test_live_localhost.py::test_live_list_scan_history PASSED
tests/test_live_localhost.py::test_live_get_host_summary PASSED

7 passed in 55.83s
```
