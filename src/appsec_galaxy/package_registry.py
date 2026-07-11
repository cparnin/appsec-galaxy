"""
Package Registry Client for AppSec Galaxy Dependency Analysis

Queries package registries (npm, PyPI, Go proxy, crates.io, etc.) to assess
package health: last publish date, download counts, deprecation status.

Results are cached in-memory with configurable TTL and rate-limited to avoid
abuse of public registries.
"""

import time
import logging
from typing import Any
from dataclasses import dataclass
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class PackageHealthInfo:
    """Health metadata for a single package."""
    package_name: str
    ecosystem: str
    latest_version: str = ''
    last_publish_date: str | None = None  # ISO 8601
    weekly_downloads: int = 0
    deprecated: bool = False
    archived: bool = False
    health_status: str = 'unknown'  # healthy | stale | abandoned | dead | unknown
    months_since_update: float = 0.0
    error: str = ''


class PackageRegistryClient:
    """
    Queries public package registries with in-memory caching and rate limiting.

    Supports: npm, PyPI, Go proxy, crates.io, Packagist, Maven Central, RubyGems.
    Gracefully degrades when offline: returns 'unknown' health status.
    """

    # Registry base URLs
    REGISTRY_URLS = {
        'npm': 'https://registry.npmjs.org',
        'pypi': 'https://pypi.org/pypi',
        'go': 'https://proxy.golang.org',
        'cargo': 'https://crates.io/api/v1/crates',
        'packagist': 'https://repo.packagist.org/p2',
        'maven': 'https://search.maven.org/solrsearch/select',
        'rubygems': 'https://rubygems.org/api/v1/gems',
    }

    def __init__(self, cache_ttl: int = 3600, rate_limit_per_sec: float = 10.0):
        self._cache: dict[str, dict[str, Any]] = {}  # key -> {data, expires_at}
        self._cache_ttl = cache_ttl
        self._min_interval = 1.0 / rate_limit_per_sec
        self._last_request_time = 0.0
        self._request_timeout = 10  # seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_package_health(
        self, name: str, ecosystem: str, installed_version: str = ''
    ) -> PackageHealthInfo:
        """
        Check package health against its registry.

        Returns a PackageHealthInfo with health_status set to one of:
            healthy : published within PACKAGE_STALE_MONTHS
            stale   : between PACKAGE_STALE_MONTHS and PACKAGE_ABANDONED_MONTHS
            abandoned: exceeds PACKAGE_ABANDONED_MONTHS
            dead    : removed, archived, or deprecated
            unknown : could not reach registry or unsupported ecosystem
        """
        from appsec_galaxy.config import PACKAGE_STALE_MONTHS, PACKAGE_ABANDONED_MONTHS

        cache_key = f"{ecosystem}:{name}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        info = PackageHealthInfo(package_name=name, ecosystem=ecosystem)

        if not REQUESTS_AVAILABLE:
            info.health_status = 'unknown'
            info.error = 'requests library not available'
            self._set_cached(cache_key, info)
            return info

        try:
            raw = self._fetch_registry_data(name, ecosystem)
            if raw is None:
                info.health_status = 'unknown'
                info.error = f'unsupported ecosystem: {ecosystem}'
                self._set_cached(cache_key, info)
                return info

            info.latest_version = raw.get('latest_version', '')
            info.last_publish_date = raw.get('last_publish_date', '')
            info.weekly_downloads = raw.get('weekly_downloads', 0)
            info.deprecated = raw.get('deprecated', False)
            info.archived = raw.get('archived', False)

            # Classify health
            if info.deprecated or info.archived:
                info.health_status = 'dead'
            elif info.last_publish_date:
                months = self._months_since(info.last_publish_date)
                info.months_since_update = months
                if months > PACKAGE_ABANDONED_MONTHS:
                    info.health_status = 'abandoned'
                elif months > PACKAGE_STALE_MONTHS:
                    info.health_status = 'stale'
                else:
                    info.health_status = 'healthy'
            else:
                info.health_status = 'unknown'

        except Exception as e:
            logger.debug(f"Registry lookup failed for {ecosystem}/{name}: {e}")
            info.health_status = 'unknown'
            info.error = str(e)

        self._set_cached(cache_key, info)
        return info

    # ------------------------------------------------------------------
    # Registry-specific fetchers
    # ------------------------------------------------------------------

    def _fetch_registry_data(self, name: str, ecosystem: str) -> dict[str, Any] | None:
        """Dispatch to the correct registry fetcher."""
        fetchers = {
            'npm': self._fetch_npm,
            'pypi': self._fetch_pypi,
            'go': self._fetch_go,
            'cargo': self._fetch_cargo,
            'packagist': self._fetch_packagist,
            'maven': self._fetch_maven,
            'rubygems': self._fetch_rubygems,
        }
        fetcher = fetchers.get(ecosystem)
        if fetcher is None:
            return None
        return fetcher(name)

    def _fetch_npm(self, name: str) -> dict[str, Any]:
        """Fetch npm registry metadata."""
        # Use abbreviated metadata endpoint for speed
        url = f"{self.REGISTRY_URLS['npm']}/{name}"
        headers = {'Accept': 'application/vnd.npm.install-v1+json'}
        data = self._http_get(url, headers=headers)
        if data is None:
            # Fallback to full metadata
            data = self._http_get(f"{self.REGISTRY_URLS['npm']}/{name}")
            if data is None:
                return {'latest_version': '', 'last_publish_date': ''}

        dist_tags = data.get('dist-tags', {})
        latest = dist_tags.get('latest', '')
        modified = data.get('time', {}).get('modified', '') or data.get('modified', '')

        # Check deprecation
        deprecated = False
        versions = data.get('versions', {})
        if latest and latest in versions:
            deprecated = bool(versions[latest].get('deprecated'))

        return {
            'latest_version': latest,
            'last_publish_date': modified,
            'deprecated': deprecated,
            'archived': False,
            'weekly_downloads': 0,  # Would need separate API call
        }

    def _fetch_pypi(self, name: str) -> dict[str, Any]:
        """Fetch PyPI registry metadata."""
        url = f"{self.REGISTRY_URLS['pypi']}/{name}/json"
        data = self._http_get(url)
        if data is None:
            return {'latest_version': '', 'last_publish_date': ''}

        info = data.get('info', {})
        latest = info.get('version', '')
        releases = data.get('releases', {})

        # Get last upload date from latest release
        last_date = ''
        if latest and latest in releases:
            files = releases[latest]
            if files:
                last_date = files[-1].get('upload_time_iso_8601', '') or files[-1].get('upload_time', '')

        # Check classifiers for deprecated/inactive
        classifiers = info.get('classifiers', [])
        deprecated = any('Inactive' in c or 'Deprecated' in c for c in classifiers)

        return {
            'latest_version': latest,
            'last_publish_date': last_date,
            'deprecated': deprecated,
            'archived': False,
            'weekly_downloads': 0,
        }

    def _fetch_go(self, name: str) -> dict[str, Any]:
        """Fetch Go module proxy metadata."""
        url = f"{self.REGISTRY_URLS['go']}/{name}/@latest"
        data = self._http_get(url)
        if data is None:
            return {'latest_version': '', 'last_publish_date': ''}

        return {
            'latest_version': data.get('Version', ''),
            'last_publish_date': data.get('Time', ''),
            'deprecated': data.get('Deprecated', False) if isinstance(data.get('Deprecated'), bool) else False,
            'archived': False,
            'weekly_downloads': 0,
        }

    def _fetch_cargo(self, name: str) -> dict[str, Any]:
        """Fetch crates.io metadata."""
        url = f"{self.REGISTRY_URLS['cargo']}/{name}"
        data = self._http_get(url, headers={'User-Agent': 'AppSec-Galaxy/2.2.2'})
        if data is None:
            return {'latest_version': '', 'last_publish_date': ''}

        crate = data.get('crate', {})
        return {
            'latest_version': crate.get('newest_version', ''),
            'last_publish_date': crate.get('updated_at', ''),
            'deprecated': False,
            'archived': False,
            'weekly_downloads': crate.get('recent_downloads', 0),
        }

    def _fetch_packagist(self, name: str) -> dict[str, Any]:
        """Fetch Packagist (PHP) metadata."""
        url = f"{self.REGISTRY_URLS['packagist']}/{name}.json"
        data = self._http_get(url)
        if data is None:
            return {'latest_version': '', 'last_publish_date': ''}

        packages = data.get('packages', {}).get(name, [])
        if not packages:
            return {'latest_version': '', 'last_publish_date': ''}

        # First entry is latest
        latest = packages[0]
        return {
            'latest_version': latest.get('version', ''),
            'last_publish_date': latest.get('time', ''),
            'deprecated': bool(latest.get('abandoned')),
            'archived': False,
            'weekly_downloads': 0,
        }

    def _fetch_maven(self, name: str) -> dict[str, Any]:
        """Fetch Maven Central metadata. Name format: groupId:artifactId."""
        parts = name.split(':')
        if len(parts) != 2:
            return {'latest_version': '', 'last_publish_date': ''}

        group_id, artifact_id = parts
        url = f"{self.REGISTRY_URLS['maven']}?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
        data = self._http_get(url)
        if data is None:
            return {'latest_version': '', 'last_publish_date': ''}

        docs = data.get('response', {}).get('docs', [])
        if not docs:
            return {'latest_version': '', 'last_publish_date': ''}

        doc = docs[0]
        # Maven returns timestamp in milliseconds
        ts = doc.get('timestamp', 0)
        last_date = ''
        if ts:
            last_date = datetime.fromtimestamp(ts / 1000, tz=UTC).isoformat()

        return {
            'latest_version': doc.get('latestVersion', ''),
            'last_publish_date': last_date,
            'deprecated': False,
            'archived': False,
            'weekly_downloads': 0,
        }

    def _fetch_rubygems(self, name: str) -> dict[str, Any]:
        """Fetch RubyGems metadata."""
        url = f"{self.REGISTRY_URLS['rubygems']}/{name}.json"
        data = self._http_get(url)
        if data is None:
            return {'latest_version': '', 'last_publish_date': ''}

        return {
            'latest_version': data.get('version', ''),
            'last_publish_date': data.get('version_created_at', ''),
            'deprecated': False,
            'archived': False,
            'weekly_downloads': data.get('version_downloads', 0),
        }

    # ------------------------------------------------------------------
    # HTTP + caching helpers
    # ------------------------------------------------------------------

    def _http_get(self, url: str, headers: dict[str, str] | None = None) -> dict | None:
        """Rate-limited HTTP GET returning parsed JSON or None."""
        self._rate_limit_wait()
        try:
            resp = requests.get(url, headers=headers or {}, timeout=self._request_timeout)
            if resp.status_code == 200:
                return resp.json()
            logger.debug(f"Registry returned {resp.status_code} for {url}")
            return None
        except Exception as e:
            logger.debug(f"HTTP request failed for {url}: {e}")
            return None

    def _rate_limit_wait(self):
        """Enforce minimum interval between requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()

    def _get_cached(self, key: str) -> PackageHealthInfo | None:
        """Return cached result if still valid."""
        entry = self._cache.get(key)
        if entry and time.time() < entry['expires_at']:
            return entry['data']
        return None

    def _set_cached(self, key: str, data: PackageHealthInfo):
        """Store result in cache."""
        self._cache[key] = {
            'data': data,
            'expires_at': time.time() + self._cache_ttl,
        }

    @staticmethod
    def _months_since(iso_date: str) -> float:
        """Return approximate months since an ISO 8601 date string."""
        try:
            # Handle various ISO formats
            date_str = iso_date.replace('Z', '+00:00')
            # Strip microseconds beyond 6 digits for Python compatibility
            if '.' in date_str:
                base, frac_and_tz = date_str.split('.', 1)
                # Find where timezone starts
                for i, c in enumerate(frac_and_tz):
                    if c in ('+', '-') and i > 0:
                        frac = frac_and_tz[:i][:6]
                        tz = frac_and_tz[i:]
                        date_str = f"{base}.{frac}{tz}"
                        break
                else:
                    # No timezone found, might just be fractional seconds
                    frac = frac_and_tz[:6]
                    date_str = f"{base}.{frac}+00:00"

            dt = datetime.fromisoformat(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            delta = datetime.now(UTC) - dt
            return delta.days / 30.44  # Average days per month
        except (ValueError, TypeError):
            return 0.0
