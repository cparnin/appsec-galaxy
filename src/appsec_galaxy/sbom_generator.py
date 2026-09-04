#!/usr/bin/env python3
"""
SBOM Generation with Syft Integration

Generates Software Bill of Materials (SBOM) for supply chain security compliance.
Supports multiple output formats and integrates with existing vulnerability data.
"""

import asyncio
import json
import subprocess
import logging
from pathlib import Path
from typing import Any
from datetime import datetime

logger = logging.getLogger(__name__)

SYFT_TIMEOUT_SECONDS = 300

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

                return {
                    "success": True,
                    "sbom": sbom_data,
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

            # Same ceiling as the other scanners; a hung syft must not hang
            # the web request or MCP call forever.
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SYFT_TIMEOUT_SECONDS)
            except TimeoutError:
                process.kill()
                await process.wait()
                return {"success": False, "error": f"syft timed out after {SYFT_TIMEOUT_SECONDS}s"}

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
