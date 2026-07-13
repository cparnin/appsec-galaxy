#!/usr/bin/env python3
"""
SCA (Software Composition Analysis) Scanner

This module integrates Trivy for dependency scanning.
It can use pre-existing Trivy results from GitHub Actions or run Trivy locally.
"""

import subprocess
import json
from pathlib import Path
import logging
from typing import Any

# Import configuration constants
from appsec_galaxy.config import TRIVY_SCANNERS, format_subprocess_error
from appsec_galaxy.finding import Finding
from .validation import validate_binary_path, validate_repo_path

logger = logging.getLogger(__name__)

def run_trivy_scan(repo_path: str, output_dir: Path | None = None, scan_level: str = "critical-high") -> list[dict[str, Any]]:
    """
    Run Trivy SCA (Software Composition Analysis) scanner on the given repository.
    First checks for existing Trivy results from GitHub Actions, then runs locally if needed.
    Returns a list of findings in standardized format.
    """
    try:
        # Use provided output_dir or default
        if output_dir is None:
            from appsec_galaxy.config import BASE_OUTPUT_DIR
            out_dir = Path(BASE_OUTPUT_DIR) / "raw"
        else:
            out_dir = Path(output_dir)

        out_dir.mkdir(parents=True, exist_ok=True)
        output_file = out_dir / "trivy-sca.json"

        # Run Trivy locally
        logger.debug("Running Trivy scan locally")
        if not _run_trivy_scan(repo_path, output_file, scan_level):
            return []

        # Parse and return findings from the JSON output
        return _parse_trivy_results(output_file, repo_path)

    except Exception as e:
        logger.error(f"Error in SCA scan: {e}")
        return []

def _run_trivy_scan(repo_path: str, output_file: Path, scan_level: str = "critical-high") -> bool:
    """Run Trivy scan locally and return True if successful."""
    try:
        # Validate and sanitize repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            return False

        # Check what dependency files exist to provide better feedback
        dep_files = []
        dep_patterns = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock", "pom.xml", "build.gradle"
        ]

        for pattern in dep_patterns:
            matches = list(repo_path_obj.rglob(pattern))
            dep_files.extend(matches)

        if dep_files:
            logger.debug(f"Found dependency files: {[f.name for f in dep_files[:5]]}")
        else:
            logger.debug("No common dependency files found - scanning filesystem anyway")

        # Get and validate Trivy binary path
        trivy_bin = validate_binary_path('TRIVY_BIN', 'trivy')
        if not trivy_bin:
            logger.error("Could not validate trivy binary")
            return False

        # Delete old output file BEFORE running to prevent loading stale results
        if output_file.exists():
            output_file.unlink()
            logger.debug(f"Deleted old trivy output file: {output_file}")

        # Severity filter follows scan level: "all" includes medium/low, otherwise crit/high.
        sev = "CRITICAL,HIGH,MEDIUM,LOW" if scan_level == "all" else "CRITICAL,HIGH"

        # Run Trivy filesystem scan for vulnerabilities plus (by default)
        # IaC/config misconfigurations; APPSEC_TRIVY_SCANNERS controls the set.
        cmd = [
            trivy_bin, "fs",
            "--format", "json",
            "--output", str(output_file),
            "--severity", sev,
            "--scanners", TRIVY_SCANNERS,
            "--list-all-pkgs",  # List all packages even without lockfiles
            "--quiet",
            str(repo_path_obj)
        ]

        logger.debug(f"Running Trivy SCA scan on {repo_path_obj}")
        # Use subprocess.run with shell=False for security
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, shell=False)

        if result.returncode != 0:
            # Trivy may return non-zero even on successful scans with findings
            # Only treat as error if no output file was created
            if not output_file.exists():
                error_details = format_subprocess_error('trivy', result.returncode, result.stderr, result.stdout)
                logger.error(error_details)
                return False
            else:
                logger.info(f"Trivy returned code {result.returncode} but created output file - continuing")

        # If the root scan found no results, fall back to scanning vendor directories.
        # This handles projects that have installed dependencies (node_modules, vendor/)
        # but no lockfile at the repo root: a common pattern across Node.js, Go, PHP,
        # and Ruby projects.
        if output_file.exists():
            try:
                with open(output_file, encoding='utf-8') as f:
                    root_data = json.load(f)
                root_results = root_data.get('Results') or []
                # Misconfig results alone (e.g. a Dockerfile hit) must not mask
                # a missing-lockfile situation, so key the fallback off
                # vulnerability results specifically.
                if not any(r.get('Vulnerabilities') for r in root_results):
                    vendor_dirs = ['node_modules', 'vendor']
                    extra_results = []
                    for vdir in vendor_dirs:
                        vendor_path = repo_path_obj / vdir
                        if not vendor_path.is_dir():
                            continue
                        logger.info(f"Root scan found no results; scanning vendor dir: {vendor_path}")
                        tmp_out = output_file.parent / f"trivy-{vdir}-tmp.json"
                        # Vendor dirs are vuln-only: misconfig hits inside
                        # node_modules/vendor are third-party noise.
                        vendor_cmd = [
                            trivy_bin, "fs",
                            "--format", "json",
                            "--output", str(tmp_out),
                            "--severity", sev,
                            "--scanners", "vuln",
                            "--list-all-pkgs",
                            "--quiet",
                            str(vendor_path)
                        ]
                        subprocess.run(
                            vendor_cmd, capture_output=True, text=True, timeout=300, shell=False
                        )
                        if tmp_out.exists():
                            with open(tmp_out, encoding='utf-8') as f:
                                vendor_data = json.load(f)
                            extra_results.extend(vendor_data.get('Results', []))
                            tmp_out.unlink()
                    if extra_results:
                        root_data['Results'] = root_results + extra_results
                        with open(output_file, 'w', encoding='utf-8') as f:
                            json.dump(root_data, f)
                        logger.info(f"Vendor fallback added {len(extra_results)} result sets to Trivy output")
            except Exception as e:
                logger.warning(f"Vendor directory fallback failed: {e}")

        return True

    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('trivy', 124, "Process timed out after 5 minutes")
        logger.error(timeout_msg)
        return False
    except FileNotFoundError:
        not_found_msg = format_subprocess_error('trivy', 127, "Trivy command not found in PATH")
        logger.error(not_found_msg)
        return False
    except Exception as e:
        logger.error(f"Error running Trivy scan: {e}")
        return False

def _parse_trivy_results(output_file: Path, repo_path: str) -> list[dict[str, Any]]:
    """Parse Trivy JSON results and return standardized findings."""
    try:
        if not output_file.exists():
            logger.info("Trivy found no vulnerabilities (no output file)")
            return []

        # Check for dependency files to provide context
        repo_path_obj = Path(repo_path)
        dep_patterns = [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock", "pom.xml", "build.gradle"
        ]
        dep_files = []
        for pattern in dep_patterns:
            matches = list(repo_path_obj.rglob(pattern))
            dep_files.extend(matches)

        with open(output_file, encoding='utf-8') as f:
            data = json.load(f)

        # Transform Trivy output to standardized format
        standardized_findings = []
        results = data.get("Results", [])

        # Count what was scanned
        scanned_targets = len(results)
        total_vulnerabilities = 0
        total_misconfigs = 0

        for result in results:
            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities", [])
            total_vulnerabilities += len(vulnerabilities)

            for vuln in vulnerabilities:
                standardized_findings.append(Finding.from_trivy(vuln, target).to_dict())

            misconfigs = result.get("Misconfigurations", [])
            total_misconfigs += len(misconfigs)
            for misconf in misconfigs:
                standardized_findings.append(Finding.from_trivy_misconfig(misconf, target).to_dict())

        if scanned_targets > 0 and not standardized_findings:
            logger.info(f"Trivy scanned {scanned_targets} targets - no vulnerabilities or misconfigurations found")
        elif standardized_findings:
            logger.info(
                f"Trivy found {total_vulnerabilities} dependency vulnerabilities and "
                f"{total_misconfigs} misconfigurations across {scanned_targets} targets"
            )
        else:
            logger.info("Trivy found no dependency files to scan")
            # Check if this is a Gradle/Maven project without lockfiles
            if dep_files:
                gradle_files = [f for f in dep_files if 'gradle' in str(f).lower()]
                maven_files = [f for f in dep_files if 'pom.xml' in str(f).lower()]
                if gradle_files or maven_files:
                    logger.warning("⚠️  Gradle/Maven project detected but no lockfiles found")
                    logger.warning("    → Trivy requires lockfiles or built artifacts to scan Java dependencies")
                    logger.warning("    → Run 'gradle dependencies --write-locks' or build the project first")
                    logger.warning("    → Alternatively, scan the built JAR: trivy image your-app.jar")

        return standardized_findings

    except Exception as e:
        logger.error(f"Error parsing Trivy results: {e}")
        return []
