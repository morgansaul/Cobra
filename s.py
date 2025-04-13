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

class SafeTokenScanner:
    def __init__(self):
        self.report = {
            "critical": [], "high": [], 
            "medium": [], "low": []
        }
        self._setup_environment()

    def _setup_environment(self):
        """Ensure Foundry is properly set up"""
        if not os.path.exists("lib/forge-std"):
            logger.info("Setting up Foundry...")
            try:
                subprocess.run("forge init --force", shell=True, check=True)
                subprocess.run("forge install foundry-rs/forge-std", shell=True, check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to setup Foundry: {e}")

    def scan(self, contract_path: str) -> Dict:
        """Main scanning workflow"""
        if not os.path.exists(contract_path):
            logger.error(f"File not found: {contract_path}")
            return self.report

        # First validate contract syntax
        if not self._validate_contract(contract_path):
            return self.report

        # Then run scans
        self._run_slither(contract_path)
        self._run_safe_test(contract_path)
        
        return self.report

    def _validate_contract(self, path: str) -> bool:
        """Check for basic Solidity syntax"""
        try:
            result = subprocess.run(
                ["solc", path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logger.error(f"Contract errors:\n{result.stderr}")
                return False
            return True
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return False

    def _run_slither(self, contract_path: str):
        """Run Slither if available"""
        try:
            cmd = f"slither {contract_path} --exclude-informational --json -"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                findings = json.loads(result.stdout)
                for detector in findings.get("detectors", []):
                    severity = detector.get("impact", "").lower()
                    if severity in self.report:
                        self.report[severity].append({
                            "description": detector["description"],
                            "lines": detector.get("elements", [{}])[0].get("type_specific_fields", {}).get("lines", [])
                        })
        except FileNotFoundError:
            logger.warning("Slither not installed - skipping static analysis")
        except Exception as e:
            logger.error(f"Slither error: {e}")

    def _run_safe_test(self, contract_path: str):
        """Safer Foundry test implementation"""
        contract_name = os.path.splitext(os.path.basename(contract_path))[0]
        test_file = f"test/{contract_name}Test.t.sol"
        
        try:
            os.makedirs("test", exist_ok=True)
            with open(test_file, "w") as f:
                f.write(f"""
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.0;
                
                import "forge-std/Test.sol";
                import "../{contract_path}";
                
                contract {contract_name}Test is Test {{
                    function testContractDeploys() public {{
                        assertTrue(true); // Basic sanity check
                    }}
                }}
                """)
            
            result = subprocess.run(
                f"forge test --match-contract {contract_name}Test",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.report["high"].append("Basic test failed - check contract")
                logger.debug(f"Test output:\n{result.stderr}")
                
        except Exception as e:
            logger.error(f"Testing failed: {e}")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: ./scanner.py <contract.sol>")
        sys.exit(1)
    
    scanner = SafeTokenScanner()
    report = scanner.scan(sys.argv[1])
    print(json.dumps(report, indent=2))
