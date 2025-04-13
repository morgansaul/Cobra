#!/usr/bin/env python3
import json
import os
import subprocess
import logging
from typing import Dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RobustTokenScanner:
    def __init__(self):
        self.report = {
            "critical": [], "high": [],
            "medium": [], "low": []
        }
        self._setup_environment()

    def _setup_environment(self):
        """Configure environment for scanning"""
        try:
            # Setup Git if not configured
            if not os.path.exists(os.path.expanduser("~/.gitconfig")):
                subprocess.run("git config --global user.email 'scan@security.local'", shell=True)
                subprocess.run("git config --global user.name 'Security Scanner'", shell=True)
            
            # Initialize Foundry without Git
            if not os.path.exists("lib/forge-std"):
                logger.info("Setting up Foundry...")
                subprocess.run("mkdir -p lib", shell=True)
                subprocess.run("git clone https://github.com/foundry-rs/forge-std.git lib/forge-std", shell=True)
        except Exception as e:
            logger.error(f"Setup error: {e}")

    def scan(self, contract_path: str) -> Dict:
        """Main scanning workflow"""
        if not os.path.exists(contract_path):
            logger.error(f"File not found: {contract_path}")
            return self.report

        # Verify Solidity version compatibility
        if not self._check_solidity_version(contract_path):
            return self.report

        # Run security checks
        self._run_slither(contract_path)
        self._run_basic_checks(contract_path)
        
        return self.report

    def _check_solidity_version(self, path: str) -> bool:
        """Check contract's Solidity version"""
        try:
            with open(path, "r") as f:
                first_line = f.readline().strip()
                if "pragma solidity" in first_line:
                    required_version = first_line.split("^")[-1].replace(";", "")
                    result = subprocess.run(
                        f"solc-select use {required_version}",
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        logger.error(f"Need Solidity {required_version}. Install with: solc-select install {required_version}")
                        return False
            return True
        except Exception as e:
            logger.error(f"Version check failed: {e}")
            return False

    def _run_slither(self, contract_path: str):
        """Run Slither analysis"""
        try:
            cmd = f"slither {contract_path} --exclude-informational --json -"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                findings = json.loads(result.stdout)
                for detector in findings.get("detectors", []):
                    severity = detector.get("impact", "").lower()
                    if severity in self.report:
                        self.report[severity].append({
                            "issue": detector["description"],
                            "lines": detector.get("elements", [{}])[0].get("type_specific_fields", {}).get("lines", [])
                        })
        except Exception as e:
            logger.error(f"Slither error: {e}")

    def _run_basic_checks(self, contract_path: str):
        """Basic pattern matching checks"""
        try:
            with open(contract_path, "r") as f:
                content = f.read()
                checks = {
                    "critical": [".call{value:", "delegatecall("],
                    "high": ["mint(", "onlyOwner"],
                    "medium": ["block.timestamp"]
                }
                for severity, patterns in checks.items():
                    for pattern in patterns:
                        if pattern in content:
                            self.report[severity].append(f"Pattern detected: {pattern}")
        except Exception as e:
            logger.error(f"Basic checks failed: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <contract.sol>")
        sys.exit(1)
    
    scanner = RobustTokenScanner()
    report = scanner.scan(sys.argv[1])
    print(json.dumps(report, indent=2))
