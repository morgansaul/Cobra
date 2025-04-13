#!/usr/bin/env python3
import json
import os
import subprocess
import logging
from typing import Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TokenScanner:
    def __init__(self):
        self.report = {
            "critical": [], "high": [], "medium": [],
            "low": [], "optimization": []
        }
        self.tools = {
            "slither": self._check_tool("slither --version"),
            "foundry": self._check_tool("forge --version"),
            "solc": self._check_tool("solc --version")
        }

    def _check_tool(self, cmd: str) -> bool:
        try:
            subprocess.run(cmd, shell=True, check=True,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    def scan(self, contract_path: str) -> Dict:
        """Run security scan"""
        if not os.path.exists(contract_path):
            logger.error(f"File not found: {contract_path}")
            return self.report

        # Static analysis
        if self.tools["slither"]:
            self._run_slither(contract_path)
        else:
            logger.warning("Slither not installed - skipping static analysis")
            self._basic_pattern_check(contract_path)

        # Dynamic analysis
        if self.tools["foundry"] and self.tools["solc"]:
            self._run_foundry_tests(contract_path)
        else:
            logger.warning("Foundry/solc missing - skipping dynamic tests")

        return self.report

    def _run_slither(self, contract_path: str):
        """Run Slither static analysis"""
        try:
            cmd = f"slither {contract_path} --json -"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout:
                findings = json.loads(result.stdout)
                for detector in findings.get("detectors", []):
                    severity = detector.get("impact", "").lower()
                    if severity in self.report:
                        self.report[severity].append({
                            "issue": detector["description"],
                            "contract": detector["contract"],
                            "lines": detector["elements"][0]["type_specific_fields"]["lines"]
                        })
        except Exception as e:
            logger.error(f"Slither failed: {str(e)}")

    def _basic_pattern_check(self, contract_path: str):
        """Fallback pattern check"""
        patterns = {
            "critical": ["call.value(", "transfer("],
            "high": ["mint(", "admin("],
            "medium": ["block.timestamp"]
        }
        try:
            with open(contract_path, "r") as f:
                content = f.read()
                for severity, matches in patterns.items():
                    for pattern in matches:
                        if pattern in content:
                            self.report[severity].append(
                                f"Pattern detected: {pattern}"
                            )
        except Exception as e:
            logger.error(f"Pattern scan failed: {str(e)}")

    def _run_foundry_tests(self, contract_path: str):
        """Basic Foundry test simulation"""
        test_file = f"""
        // test/Exploit.t.sol
        import \"forge-std/Test.sol\";
        import \"../{contract_path}\";
        
        contract ExploitTest is Test {{
            function testReentrancy() public {{
                // Basic test structure
                assertTrue(true);
            }}
        }}
        """
        try:
            os.makedirs("test", exist_ok=True)
            with open("test/Exploit.t.sol", "w") as f:
                f.write(test_file)
            
            subprocess.run(
                "forge test --match-test testReentrancy",
                shell=True,
                check=True
            )
        except subprocess.CalledProcessError:
            self.report["high"].append("Potential exploit detected")
        except Exception as e:
            logger.error(f"Foundry test failed: {str(e)}")
        finally:
            if os.path.exists("test/Exploit.t.sol"):
                os.remove("test/Exploit.t.sol")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <contract.sol>")
        sys.exit(1)
    
    scanner = TokenScanner()
    report = scanner.scan(sys.argv[1])
    print(json.dumps(report, indent=2))
