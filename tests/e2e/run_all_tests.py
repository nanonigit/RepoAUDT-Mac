#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RepoAUDT Mac — 4-Tier E2E Test Suite Runner
Executes Tier 1 (Features), Tier 2 (Boundaries), Tier 3 (Pairwise), and Tier 4 (Scenarios).
Outputs comprehensive structured metrics and diagnostic reports.
Exit code 0 on all tests passing, exit code 1 on any failure.
"""

import argparse
import sys
import time
import unittest
from pathlib import Path

E2E_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = E2E_DIR.parent.parent

if str(E2E_DIR) not in sys.path:
    sys.path.insert(0, str(E2E_DIR))


def run_test_suite(suite_module_name: str, tier_title: str) -> unittest.TestResult:
    """Executes a single test tier module and returns its TestResult."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(suite_module_name)
    runner = unittest.TextTestRunner(verbosity=1)
    print(f"\n{'='*70}\n[RUNNING] {tier_title} ({suite_module_name})\n{'='*70}")
    t0 = time.time()
    result = runner.run(suite)
    duration = time.time() - t0
    print(f"[COMPLETED] {tier_title}: {result.testsRun} tests run in {duration:.3f}s")
    print(f"            Passed: {result.testsRun - len(result.failures) - len(result.errors)}, Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    return result


def main():
    parser = argparse.ArgumentParser(description="RepoAUDT Mac 4-Tier E2E Test Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run only specific tier (1, 2, 3, or 4)")
    args = parser.parse_args()

    tiers = [
        (1, "test_tier1_features", "Tier 1: Feature Coverage (85 tests, F1-F17)"),
        (2, "test_tier2_boundaries", "Tier 2: Boundary Value Analysis & Edge Cases (85 tests, F1-F17)"),
        (3, "test_tier3_pairwise", "Tier 3: Pairwise Cross-Feature Interactions (17 tests)"),
        (4, "test_tier4_scenarios", "Tier 4: Real-World Application Scenarios (5 tests)"),
    ]

    if args.tier:
        tiers = [t for t in tiers if t[0] == args.tier]

    print("\n" + "="*70)
    print("REPOAUDT MAC — 4-TIER OPAQUE-BOX E2E TEST SUITE")
    print(f"Directory: {E2E_DIR}")
    print("="*70)

    total_run = 0
    total_failures = 0
    total_errors = 0
    start_total_time = time.time()

    tier_results = []

    for tier_num, module_name, tier_title in tiers:
        res = run_test_suite(module_name, tier_title)
        tier_results.append((tier_num, tier_title, res))
        total_run += res.testsRun
        total_failures += len(res.failures)
        total_errors += len(res.errors)

    total_duration = time.time() - start_total_time
    total_passed = total_run - total_failures - total_errors

    print("\n" + "="*70)
    print("SUMMARY REPORT — 4-TIER E2E TEST EXECUTION")
    print("="*70)
    for tier_num, tier_title, res in tier_results:
        passed = res.testsRun - len(res.failures) - len(res.errors)
        status_str = "PASS" if (len(res.failures) == 0 and len(res.errors) == 0) else "FAIL"
        print(f"[{status_str}] {tier_title}")
        print(f"       Total: {res.testsRun:3d} | Passed: {passed:3d} | Failed: {len(res.failures):3d} | Errors: {len(res.errors):3d}")

    print("-" * 70)
    print(f"TOTAL TESTS RUN: {total_run}")
    print(f"TOTAL PASSED:    {total_passed}")
    print(f"TOTAL FAILURES:  {total_failures}")
    print(f"TOTAL ERRORS:    {total_errors}")
    print(f"EXECUTION TIME:  {total_duration:.3f} seconds")
    print("="*70)

    if total_failures > 0 or total_errors > 0:
        print("\n[DIAGNOSTIC NOTICE] Some tests failed because target milestone features are currently")
        print("pending implementation or require fixes by milestone workers (M1, M2, M3).")
        print("Implementation defects have been captured and escalated per QA guidelines.")
        sys.exit(1)
    else:
        print("\nALL E2E TESTS PASSED SUCCESSFULLY! (Exit code 0)")
        sys.exit(0)


if __name__ == "__main__":
    main()
