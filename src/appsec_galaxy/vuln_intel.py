"""
Exploit intelligence enrichment: EPSS scores and CISA KEV membership.

Raw CVSS severity says how bad a vulnerability could be; EPSS (Exploit
Prediction Scoring System) says how likely it is to be exploited in the next
30 days, and the CISA KEV catalog lists CVEs with confirmed in-the-wild
exploitation. Enriching Trivy findings with both lets remediation focus on
what attackers actually use.

Adds to each Trivy finding that has a CVE id:
    epss_score        float 0..1 (probability of exploitation)
    in_kev            bool (confirmed exploited per CISA)
    exploit_priority  'urgent' (KEV) | 'high' (EPSS >= 0.1) | 'normal'

Controlled by APPSEC_VULN_INTEL (default true). All network calls have short
timeouts and fail open: no internet means no enrichment, never a broken scan.
The KEV catalog is cached on disk for 24 hours.
"""

import json
import os
import tempfile
import time
from typing import Any

import requests

from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_BATCH_SIZE = 100
_REQUEST_TIMEOUT = 10
_KEV_CACHE_TTL_SECONDS = 24 * 3600
_EPSS_HIGH_THRESHOLD = 0.1


def _kev_cache_path() -> str:
    return os.path.join(tempfile.gettempdir(), "appsec_galaxy_kev_cache.json")


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Batch-fetch EPSS scores. Returns {} on any failure (fail open)."""
    scores: dict[str, float] = {}
    unique = sorted({c for c in cve_ids if c and c.upper().startswith('CVE-')})
    for i in range(0, len(unique), _EPSS_BATCH_SIZE):
        batch = unique[i:i + _EPSS_BATCH_SIZE]
        try:
            resp = requests.get(EPSS_API_URL, params={'cve': ','.join(batch)}, timeout=_REQUEST_TIMEOUT)
            resp.raise_for_status()
            for item in resp.json().get('data', []):
                try:
                    scores[item['cve']] = float(item['epss'])
                except (KeyError, TypeError, ValueError):
                    continue
        except (requests.RequestException, ValueError) as e:
            logger.warning(f"EPSS lookup failed (continuing without): {e}")
            return scores
    return scores


def fetch_kev_cves() -> set[str]:
    """CVE ids in the CISA KEV catalog, disk-cached for 24h. Empty set on failure."""
    cache = _kev_cache_path()
    try:
        if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < _KEV_CACHE_TTL_SECONDS:
            with open(cache) as f:
                return set(json.load(f))
    except (OSError, json.JSONDecodeError):
        pass  # corrupt/unreadable cache: refetch below

    try:
        resp = requests.get(KEV_URL, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        cves = {v.get('cveID', '') for v in resp.json().get('vulnerabilities', []) if v.get('cveID')}
    except (requests.RequestException, ValueError) as e:
        logger.warning(f"CISA KEV fetch failed (continuing without): {e}")
        return set()

    try:
        with open(cache, 'w') as f:
            json.dump(sorted(cves), f)
    except OSError:
        pass  # cache write is best-effort
    return cves


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich Trivy CVE findings in place with EPSS/KEV intel.

    No-op when APPSEC_VULN_INTEL=false or there are no CVE findings.
    Always returns the findings list (fail open).
    """
    if os.getenv('APPSEC_VULN_INTEL', 'true').lower() != 'true':
        return findings

    cve_findings = [f for f in findings
                    if f.get('tool') == 'trivy' and str(f.get('vulnerability_id', '')).upper().startswith('CVE-')]
    if not cve_findings:
        return findings

    try:
        cve_ids = [f['vulnerability_id'] for f in cve_findings]
        epss = fetch_epss_scores(cve_ids)
        kev = fetch_kev_cves()
    except Exception as e:
        logger.warning(f"Vulnerability intel enrichment failed (continuing without): {e}")
        return findings

    urgent = high = 0
    for f in cve_findings:
        cve = f['vulnerability_id']
        score = epss.get(cve)
        in_kev = cve in kev
        if score is not None:
            f['epss_score'] = score
        f['in_kev'] = in_kev
        if in_kev:
            f['exploit_priority'] = 'urgent'
            urgent += 1
        elif score is not None and score >= _EPSS_HIGH_THRESHOLD:
            f['exploit_priority'] = 'high'
            high += 1
        else:
            f['exploit_priority'] = 'normal'

    if urgent or high:
        logger.info(f"Exploit intel: {urgent} KEV (actively exploited), {high} high-EPSS finding(s)")
    return findings
