#!/usr/bin/env python3
"""
Test runner script for OSINT Platform
Provides an easy way to run different test suites
"""
import os
import sys
import subprocess
import argparse


def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {cmd}")
    print(f"{'='*60}")
    
    result = subprocess.run(cmd, shell=True, capture_output=False)
    if result.returncode != 0:
        print(f"\n❌ {description} failed with exit code {result.returncode}")
        return False
    else:
        print(f"\n✅ {description} completed successfully")
        return True


def main():
    parser = argparse.ArgumentParser(description='OSINT Platform Test Runner')
    parser.add_argument('--type', choices=['unit', 'integration', 'e2e', 'all', 'coverage'],
                       default='unit', help='Type of tests to run')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--fail-fast', action='store_true',
                       help='Stop on first failure')
    parser.add_argument('--coverage-threshold', type=int, default=80,
                       help='Coverage threshold percentage')
    
    args = parser.parse_args()
    
    # Change to the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Check if pytest is installed
    try:
        subprocess.run(['pytest', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ pytest not found. Please install test dependencies:")
        print("   pip install -r requirements.txt")
        sys.exit(1)
    
    success = True
    
    # Build base pytest command
    base_cmd = "pytest"
    if args.verbose:
        base_cmd += " -v"
    if args.fail_fast:
        base_cmd += " --maxfail=1"
    
    # Run tests based on type
    if args.type == 'unit':
        cmd = f"{base_cmd} tests/unit/"
        success = run_command(cmd, "Unit Tests")
        
    elif args.type == 'integration':
        cmd = f"{base_cmd} tests/integration/"
        success = run_command(cmd, "Integration Tests")
        
    elif args.type == 'e2e':
        cmd = f"{base_cmd} tests/e2e/"
        success = run_command(cmd, "End-to-End Tests")
        
    elif args.type == 'coverage':
        cmd = f"{base_cmd} --cov=. --cov-report=html --cov-report=term-missing --cov-fail-under={args.coverage_threshold}"
        success = run_command(cmd, f"All Tests with Coverage (threshold: {args.coverage_threshold}%)")
        
        if success:
            print(f"\n📊 Coverage report generated in htmlcov/index.html")
            
    elif args.type == 'all':
        # Run all test types in sequence
        test_types = [
            (f"{base_cmd} tests/unit/", "Unit Tests"),
            (f"{base_cmd} tests/integration/", "Integration Tests"),
            (f"{base_cmd} tests/e2e/", "End-to-End Tests")
        ]
        
        for cmd, description in test_types:
            if not run_command(cmd, description):
                success = False
                if args.fail_fast:
                    break
    
    # Summary
    print(f"\n{'='*60}")
    if success:
        print("🎉 All tests completed successfully!")
    else:
        print("❌ Some tests failed. Check output above for details.")
    print(f"{'='*60}")
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()