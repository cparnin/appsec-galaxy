#!/usr/bin/env python3
"""
SBOM Generation with Syft Integration

Generates Software Bill of Materials (SBOM) for supply chain security compliance.
Supports multiple output formats and integrates with existing vulnerability data.
"""

import json
import subprocess
import logging
from pathlib import Path
from typing import Any
from datetime import datetime

logger = logging.getLogger(__name__)

class SBOMGenerator:
    """Generate SBOM using Syft with configurable options"""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.syft_available = self._check_syft_availability()

    def _check_syft_availability(self) -> bool:
        """Check if Syft is installed and available"""
        try:
            result = subprocess.run(['syft', 'version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"✅ Syft available: {result.stdout.strip()}")
                return True
            else:
                logger.warning("❌ Syft not found. Install: https://github.com/anchore/syft#installation")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("❌ Syft not found. Install: https://github.com/anchore/syft#installation")
            return False

    async def generate_sbom(self,
                           output_format: str = "spdx-json",
                           include_files: bool = True,
                           include_packages: bool = True,
                           exclude_patterns: list[str] | None = None) -> dict[str, Any]:
        """
        Generate SBOM for the repository

        Args:
            output_format: Output format (spdx-json, cyclonedx-json, syft-json, etc.)
            include_files: Include file information in SBOM
            include_packages: Include package information in SBOM
            exclude_patterns: Patterns to exclude from analysis

        Returns:
            Dict containing SBOM data and metadata
        """
        if not self.syft_available:
            return {"error": "Syft not available", "sbom": None, "metadata": {}}

        try:
            logger.info(f"🔍 Generating SBOM for {self.repo_path} in {output_format} format...")

            # Build syft command
            cmd = ['syft', str(self.repo_path), '-o', output_format]

            # Add options based on parameters
            if not include_files:
                cmd.extend(['--exclude-binary-overlap-by-ownership'])

            # Add exclude patterns
            if exclude_patterns:
                for pattern in exclude_patterns:
                    cmd.extend(['--exclude', pattern])

            # Execute syft
            result = await self._run_syft_command(cmd)

            if result['success']:
                sbom_data = json.loads(result['output']) if result['output'] else {}

                # Add our metadata
                metadata = {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "AppSec Galaxy with Syft",
                    "repository_path": str(self.repo_path),
                    "format": output_format,
                    "options": {
                        "include_files": include_files,
                        "include_packages": include_packages,
                        "exclude_patterns": exclude_patterns or []
                    }
                }

                # Enhance SBOM with vulnerability context if available
                enhanced_sbom = await self._enhance_sbom_with_vulnerability_data(sbom_data)

                return {
                    "success": True,
                    "sbom": enhanced_sbom,
                    "metadata": metadata,
                    "format": output_format
                }
            else:
                logger.error(f"Failed to generate SBOM: {result.get('error', 'Unknown error')}")
                return {
                    "success": False,
                    "error": result.get('error', 'SBOM generation failed'),
                    "sbom": None,
                    "metadata": {}
                }

        except Exception as e:
            logger.error(f"SBOM generation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "sbom": None,
                "metadata": {}
            }

    async def _run_syft_command(self, cmd: list[str]) -> dict[str, Any]:
        """Execute syft command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout.decode('utf-8'),
                    "error": None
                }
            else:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown error"
                return {
                    "success": False,
                    "output": None,
                    "error": error_msg
                }

        except Exception as e:
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }

    async def _enhance_sbom_with_vulnerability_data(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Enhance SBOM with vulnerability data from our scans"""
        try:
            # Look for existing vulnerability scan results
            outputs_dir = Path("outputs/raw")

            vulnerability_data = {}

            # Load Trivy results if available
            trivy_file = outputs_dir / "trivy-sca.json"
            if trivy_file.exists():
                try:
                    trivy_data = json.loads(trivy_file.read_text())
                    vulnerability_data["trivy"] = trivy_data
                except Exception as e:
                    logger.debug(f"Could not load Trivy data: {e}")

            # Load Snyk results if available (from ingestion)
            snyk_file = outputs_dir / "snyk.json"
            if snyk_file.exists():
                try:
                    snyk_data = json.loads(snyk_file.read_text())
                    vulnerability_data["snyk"] = snyk_data
                except Exception as e:
                    logger.debug(f"Could not load Snyk data: {e}")

            # Enhance SBOM with vulnerability context
            if vulnerability_data:
                enhanced_sbom = sbom_data.copy()
                enhanced_sbom["vulnerabilityData"] = vulnerability_data
                enhanced_sbom["enhancedBy"] = "AppSec Galaxy"
                return enhanced_sbom

            return sbom_data

        except Exception as e:
            logger.debug(f"Could not enhance SBOM with vulnerability data: {e}")
            return sbom_data

    def generate_sbom_formats(self, base_sbom: dict[str, Any]) -> dict[str, str]:
        """Generate SBOM in multiple formats for different use cases"""
        formats = {}

        supported_formats = [
            "spdx-json",     # SPDX JSON format
            "cyclonedx-json", # CycloneDX JSON format
            "syft-json",     # Syft native JSON format
            "spdx-tag-value", # SPDX tag-value format
            "cyclonedx-xml"  # CycloneDX XML format
        ]

        for fmt in supported_formats:
            try:
                # Convert to different formats (simplified approach)
                if fmt == "spdx-json":
                    formats[fmt] = self._convert_to_spdx(base_sbom)
                elif fmt == "cyclonedx-json":
                    formats[fmt] = self._convert_to_cyclonedx(base_sbom)
                else:
                    formats[fmt] = json.dumps(base_sbom, indent=2)
            except Exception as e:
                logger.debug(f"Could not generate {fmt} format: {e}")

        return formats

    def _convert_to_spdx(self, sbom_data: dict[str, Any]) -> str:
        """Convert SBOM to SPDX format"""
        # Simplified SPDX conversion - in production, use proper SPDX library
        spdx_data: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"SBOM for {self.repo_path.name}",
            "documentNamespace": f"https://github.com/cparnin/appsec-galaxy/sbom/{self.repo_path.name}",
            "creationInfo": {
                "created": datetime.now().isoformat(),
                "creators": ["Tool: AppSec Galaxy with Syft"]
            },
            "packages": []
        }

        # Add packages from original SBOM
        if "artifacts" in sbom_data:
            for artifact in sbom_data["artifacts"]:
                package = {
                    "SPDXID": f"SPDXRef-Package-{artifact.get('name', 'unknown')}",
                    "name": artifact.get('name', 'unknown'),
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "copyrightText": "NOASSERTION"
                }

                if "version" in artifact:
                    package["versionInfo"] = artifact["version"]

                spdx_data["packages"].append(package)

        return json.dumps(spdx_data, indent=2)

    def _convert_to_cyclonedx(self, sbom_data: dict[str, Any]) -> str:
        """Convert SBOM to CycloneDX format"""
        # Simplified CycloneDX conversion - in production, use proper CycloneDX library
        cyclonedx_data: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{datetime.now().isoformat()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "AppSec Galaxy Contributors",
                        "name": "AppSec Galaxy",
                        "version": "2.2.2"
                    }
                ]
            },
            "components": []
        }

        # Add components from original SBOM
        if "artifacts" in sbom_data:
            for artifact in sbom_data["artifacts"]:
                component = {
                    "type": "library",
                    "name": artifact.get('name', 'unknown'),
                    "version": artifact.get('version', 'unknown')
                }

                if "language" in artifact:
                    component["group"] = artifact["language"]

                cyclonedx_data["components"].append(component)

        return json.dumps(cyclonedx_data, indent=2)

# Import asyncio at the top level
import asyncio

async def generate_repository_sbom(repo_path: str,
                                 output_dir: str = "outputs",
                                 formats: list[str] | None = None) -> dict[str, Any]:
    """
    Generate SBOM for a repository with multiple format support

    Args:
        repo_path: Path to repository
        output_dir: Directory to save SBOM files
        formats: List of formats to generate (defaults to common formats)

    Returns:
        Dict with generation results and file paths
    """
    if formats is None:
        formats = ["spdx-json", "cyclonedx-json"]

    generator = SBOMGenerator(repo_path)
    results = {}

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        try:
            result = await generator.generate_sbom(output_format=fmt)

            if result["success"]:
                # Save SBOM to file
                filename = f"sbom.{fmt.replace('-', '.')}"
                file_path = output_path / filename

                sbom_content = json.dumps(result["sbom"], indent=2)
                file_path.write_text(sbom_content)

                results[fmt] = {
                    "success": True,
                    "file_path": str(file_path),
                    "metadata": result["metadata"]
                }

                logger.info(f"📋 Generated {fmt} SBOM: {file_path}")
            else:
                results[fmt] = {
                    "success": False,
                    "error": result["error"]
                }

        except Exception as e:
            results[fmt] = {
                "success": False,
                "error": str(e)
            }
            logger.error(f"Failed to generate {fmt} SBOM: {e}")

    return results

if __name__ == "__main__":
    # Example usage
    async def main():
        repo_path = input("Enter repository path: ").strip()
        if not repo_path:
            repo_path = "."

        results = await generate_repository_sbom(repo_path)
        print(json.dumps(results, indent=2))

    asyncio.run(main())
