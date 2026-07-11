"""
Dependency Code Path Analyzer for AppSec Galaxy

Traces actual code paths through dependencies, classifies embedding depth,
assesses package health, and generates remediation strategies.

Inspired by the thesis that AI makes many small utility libraries unnecessary:
for each dependency: HOW is it used, HOW deeply embedded, and WHAT should we do?
"""

import ast
import json
import os
import re
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any

logger = logging.getLogger(__name__)

try:
    from .config import (
        ENABLE_DEPENDENCY_ANALYSIS, DEPENDENCY_HEALTH_CHECK,
        DEPENDENCY_INLINE_THRESHOLD,
    )
except ImportError:
    from appsec_galaxy.config import (
        ENABLE_DEPENDENCY_ANALYSIS, DEPENDENCY_HEALTH_CHECK,
        DEPENDENCY_INLINE_THRESHOLD,
    )

try:
    from .package_registry import PackageRegistryClient
except ImportError:
    from appsec_galaxy.package_registry import PackageRegistryClient



# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class DependencyUsage:
    """Full usage profile for a single dependency."""
    package_name: str
    ecosystem: str  # npm, pypi, go, cargo, packagist, maven, rubygems
    installed_version: str = ''
    manifest_file: str = ''
    import_sites: list[dict] = field(default_factory=list)   # [{file, line, imported_names}]
    call_sites: list[dict] = field(default_factory=list)     # [{file, line, function_called, context}]
    unique_apis_used: set[str] = field(default_factory=set)
    files_using: set[str] = field(default_factory=set)
    depth_score: float = 0.0           # 0.0 (trivial) to 1.0 (deep)
    depth_category: str = 'trivial'    # trivial | shallow | moderate | deep
    health_status: str = 'unknown'     # healthy | stale | abandoned | dead | vulnerable | unknown
    health_info: dict = field(default_factory=dict)
    remediation_strategy: str = 'keep'  # keep | upgrade | inline | replace | remove
    replacement_suggestion: str = ''
    has_cve: bool = False
    fixed_version: str = ''

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d['unique_apis_used'] = list(self.unique_apis_used)
        d['files_using'] = list(self.files_using)
        return d


@dataclass
class DependencyHealthReport:
    """Aggregated report for all dependencies in a repository."""
    repo_path: str
    total_dependencies: int = 0
    analyzed_dependencies: int = 0
    health_breakdown: dict[str, int] = field(default_factory=dict)
    depth_breakdown: dict[str, int] = field(default_factory=dict)
    strategy_breakdown: dict[str, int] = field(default_factory=dict)
    dependencies: list[DependencyUsage] = field(default_factory=list)
    inline_candidates: list[DependencyUsage] = field(default_factory=list)
    remove_candidates: list[DependencyUsage] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'repo_path': self.repo_path,
            'total_dependencies': self.total_dependencies,
            'analyzed_dependencies': self.analyzed_dependencies,
            'health_breakdown': self.health_breakdown,
            'depth_breakdown': self.depth_breakdown,
            'strategy_breakdown': self.strategy_breakdown,
            'dependencies': [d.to_dict() for d in self.dependencies],
            'inline_candidates': [d.to_dict() for d in self.inline_candidates],
            'remove_candidates': [d.to_dict() for d in self.remove_candidates],
        }


# ---------------------------------------------------------------------------
# Known replacements: curated mapping of libraries → modern alternatives
# ---------------------------------------------------------------------------

KNOWN_REPLACEMENTS = {
    # JavaScript / npm
    'moment': 'dayjs',
    'request': 'node-fetch or undici (built-in from Node 18+)',
    'left-pad': 'String.prototype.padStart (built-in)',
    'underscore': 'lodash (or native Array/Object methods)',
    'colors': 'picocolors or chalk',
    'uuid': 'crypto.randomUUID() (built-in from Node 19+)',
    'querystring': 'URLSearchParams (built-in)',
    'mkdirp': 'fs.mkdirSync(path, {recursive: true}) (built-in)',
    'rimraf': 'fs.rmSync(path, {recursive: true}) (built-in from Node 14+)',
    'is-odd': 'n % 2 !== 0 (inline)',
    'is-even': 'n % 2 === 0 (inline)',
    'is-number': 'typeof n === "number" && !isNaN(n) (inline)',
    'is-positive-integer': 'Number.isInteger(n) && n > 0 (inline)',
    'is-negative-zero': 'Object.is(n, -0) (inline)',
    'is-string': 'typeof s === "string" (inline)',
    'is-plain-object': 'Object.getPrototypeOf(o) === Object.prototype (inline)',
    'array-flatten': 'Array.prototype.flat() (built-in)',
    'array-unique': '[...new Set(arr)] (inline)',
    'object-assign': 'Object.assign or spread syntax (built-in)',
    'string-width': 'built-in with Intl.Segmenter (modern Node)',
    'axios': 'fetch (built-in) or undici',

    # Python / PyPI
    'pycrypto': 'pycryptodome',
    'python-dateutil': 'datetime (stdlib) for simple cases',
    'six': 'drop (Python 2 compatibility no longer needed)',
    'futures': 'concurrent.futures (stdlib in Python 3)',
    'argparse': 'already in stdlib',
    'mock': 'unittest.mock (stdlib in Python 3)',
    'nose': 'pytest',

    # Ruby / RubyGems
    'iconv': 'String#encode (built-in Ruby 1.9+)',

    # Go
    'github.com/pkg/errors': 'fmt.Errorf with %w (Go 1.13+)',
}

# Ecosystem detection from manifest files
MANIFEST_TO_ECOSYSTEM = {
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'yarn.lock': 'npm',
    'requirements.txt': 'pypi',
    'Pipfile': 'pypi',
    'pyproject.toml': 'pypi',
    'go.mod': 'go',
    'go.sum': 'go',
    'Cargo.toml': 'cargo',
    'Cargo.lock': 'cargo',
    'composer.json': 'packagist',
    'composer.lock': 'packagist',
    'pom.xml': 'maven',
    'build.gradle': 'maven',
    'Gemfile': 'rubygems',
    'Gemfile.lock': 'rubygems',
}


# ---------------------------------------------------------------------------
# Manifest Parsing
# ---------------------------------------------------------------------------

class ManifestParser:
    """Parse dependency manifests across ecosystems."""

    @staticmethod
    def parse_manifest(file_path: str) -> dict[str, str]:
        """Parse a manifest file and return {package_name: version_spec}."""
        name = Path(file_path).name
        parsers = {
            'package.json': ManifestParser._parse_package_json,
            'requirements.txt': ManifestParser._parse_requirements_txt,
            'pyproject.toml': ManifestParser._parse_pyproject_toml,
            'go.mod': ManifestParser._parse_go_mod,
            'Cargo.toml': ManifestParser._parse_cargo_toml,
            'composer.json': ManifestParser._parse_composer_json,
            'pom.xml': ManifestParser._parse_pom_xml,
            'build.gradle': ManifestParser._parse_build_gradle,
            'Gemfile': ManifestParser._parse_gemfile,
            'Pipfile': ManifestParser._parse_pipfile,
        }
        parser = parsers.get(name)
        if parser is None:
            return {}
        try:
            return parser(file_path)
        except Exception as e:
            logger.warning(f"Failed to parse {file_path}: {e}")
            return {}

    @staticmethod
    def _parse_package_json(path: str) -> dict[str, str]:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        deps = {}
        for section in ('dependencies', 'devDependencies'):
            deps.update(data.get(section, {}))
        return deps

    @staticmethod
    def _parse_requirements_txt(path: str) -> dict[str, str]:
        deps = {}
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Handle: package==1.0, package>=1.0, package~=1.0, package
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([=<>~!]+\s*.+)?', line)
                if match:
                    name = match.group(1)
                    version = (match.group(2) or '').strip()
                    deps[name] = version
        return deps

    @staticmethod
    def _parse_pyproject_toml(path: str) -> dict[str, str]:
        deps = {}
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                # Fallback: regex-based parsing
                return ManifestParser._parse_pyproject_toml_regex(path)

        with open(path, 'rb') as f:
            data = tomllib.load(f)

        # PEP 621 dependencies
        for dep_str in data.get('project', {}).get('dependencies', []):
            match = re.match(r'^([a-zA-Z0-9_.-]+)', dep_str)
            if match:
                deps[match.group(1)] = dep_str[len(match.group(1)):].strip()

        # Poetry dependencies
        for name, spec in data.get('tool', {}).get('poetry', {}).get('dependencies', {}).items():
            if name.lower() == 'python':
                continue
            if isinstance(spec, str):
                deps[name] = spec
            elif isinstance(spec, dict):
                deps[name] = spec.get('version', '')
        return deps

    @staticmethod
    def _parse_pyproject_toml_regex(path: str) -> dict[str, str]:
        """Fallback TOML parser using regex for when tomllib is unavailable."""
        deps = {}
        with open(path, encoding='utf-8') as f:
            content = f.read()
        # Match lines like "package>=1.0" inside dependencies arrays
        for match in re.finditer(r'"([a-zA-Z0-9_.-]+)([=<>~!][^"]*)"', content):
            deps[match.group(1)] = match.group(2)
        return deps

    @staticmethod
    def _parse_go_mod(path: str) -> dict[str, str]:
        deps = {}
        with open(path, encoding='utf-8') as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith('require ('):
                    in_require = True
                    continue
                if in_require and line == ')':
                    in_require = False
                    continue
                if in_require or line.startswith('require '):
                    parts = line.replace('require ', '').strip().split()
                    if len(parts) >= 2 and not parts[0].startswith('//'):
                        deps[parts[0]] = parts[1]
        return deps

    @staticmethod
    def _parse_cargo_toml(path: str) -> dict[str, str]:
        deps = {}
        with open(path, encoding='utf-8') as f:
            in_deps = False
            for line in f:
                stripped = line.strip()
                if stripped in ('[dependencies]', '[dev-dependencies]', '[build-dependencies]'):
                    in_deps = True
                    continue
                if stripped.startswith('[') and in_deps:
                    in_deps = False
                    continue
                if in_deps and '=' in stripped:
                    parts = stripped.split('=', 1)
                    name = parts[0].strip()
                    version = parts[1].strip().strip('"').strip("'")
                    # Handle table-style: name = { version = "1.0" }
                    if '{' in version:
                        vm = re.search(r'version\s*=\s*"([^"]+)"', version)
                        version = vm.group(1) if vm else ''
                    deps[name] = version
        return deps

    @staticmethod
    def _parse_composer_json(path: str) -> dict[str, str]:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        deps = {}
        for section in ('require', 'require-dev'):
            for name, ver in data.get(section, {}).items():
                if name != 'php' and not name.startswith('ext-'):
                    deps[name] = ver
        return deps

    @staticmethod
    def _parse_pom_xml(path: str) -> dict[str, str]:
        deps = {}
        try:
            # XXE defense: pom.xml comes from the scanned repo (untrusted).
            import defusedxml.ElementTree as ET
            tree = ET.parse(path)
            root = tree.getroot()
            ns = ''
            # Detect Maven namespace
            if root.tag.startswith('{'):
                ns = root.tag.split('}')[0] + '}'
            for dep in root.iter(f'{ns}dependency'):
                group = dep.find(f'{ns}groupId')
                artifact = dep.find(f'{ns}artifactId')
                version = dep.find(f'{ns}version')
                if group is not None and artifact is not None:
                    name = f"{group.text}:{artifact.text}"
                    deps[name] = version.text if version is not None else ''
        except Exception as e:
            logger.debug(f"pom.xml parse error: {e}")
        return deps

    @staticmethod
    def _parse_build_gradle(path: str) -> dict[str, str]:
        deps = {}
        with open(path, encoding='utf-8') as f:
            for line in f:
                # Match: implementation 'group:artifact:version'
                match = re.search(
                    r"(?:implementation|api|compile|testImplementation|runtimeOnly)\s+['\"]([^'\"]+)['\"]",
                    line
                )
                if match:
                    parts = match.group(1).split(':')
                    if len(parts) >= 3:
                        name = f"{parts[0]}:{parts[1]}"
                        deps[name] = parts[2]
                    elif len(parts) == 2:
                        deps[parts[0]] = parts[1]
        return deps

    @staticmethod
    def _parse_gemfile(path: str) -> dict[str, str]:
        deps = {}
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                match = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
                if match:
                    deps[match.group(1)] = match.group(2) or ''
        return deps

    @staticmethod
    def _parse_pipfile(path: str) -> dict[str, str]:
        deps = {}
        with open(path, encoding='utf-8') as f:
            in_packages = False
            for line in f:
                stripped = line.strip()
                if stripped in ('[packages]', '[dev-packages]'):
                    in_packages = True
                    continue
                if stripped.startswith('[') and in_packages:
                    in_packages = False
                    continue
                if in_packages and '=' in stripped:
                    parts = stripped.split('=', 1)
                    name = parts[0].strip()
                    version = parts[1].strip().strip('"').strip("'")
                    if version == '*':
                        version = ''
                    deps[name] = version
        return deps


# ---------------------------------------------------------------------------
# Package name → import name resolution
# ---------------------------------------------------------------------------

# Layer 3: Curated fallback for packages where name ≠ import module.
# This is the last resort: local resolution and registry resolution are tried first.
PYPI_IMPORT_NAMES = {
    # Package name → set of importable module names
    'python-dotenv': {'dotenv'},
    'gitpython': {'git'},
    'pytest-asyncio': {'pytest_asyncio'},
    'pillow': {'PIL'},
    'beautifulsoup4': {'bs4'},
    'scikit-learn': {'sklearn'},
    'scikit-image': {'skimage'},
    'pyyaml': {'yaml'},
    'pymysql': {'pymysql'},
    'python-dateutil': {'dateutil'},
    'pyjwt': {'jwt'},
    'pycryptodome': {'Crypto'},
    'pycryptodomex': {'Cryptodome'},
    'python-multipart': {'multipart'},
    'python-jose': {'jose'},
    'python-magic': {'magic'},
    'python-slugify': {'slugify'},
    'python-decouple': {'decouple'},
    'python-memcached': {'memcache'},
    'msgpack-python': {'msgpack'},
    'attrs': {'attr', 'attrs'},
    'protobuf': {'google.protobuf'},
    'grpcio': {'grpc'},
    'grpcio-tools': {'grpc_tools'},
    'opencv-python': {'cv2'},
    'opencv-python-headless': {'cv2'},
    'opencv-contrib-python': {'cv2'},
    'pyserial': {'serial'},
    'pyzmq': {'zmq'},
    'websocket-client': {'websocket'},
    'python-telegram-bot': {'telegram'},
    'google-cloud-storage': {'google.cloud.storage'},
    'google-cloud-bigquery': {'google.cloud.bigquery'},
    'google-api-python-client': {'googleapiclient'},
    'google-auth': {'google.auth'},
    'google-auth-oauthlib': {'google_auth_oauthlib'},
    'azure-storage-blob': {'azure.storage.blob'},
    'azure-identity': {'azure.identity'},
    'typing-extensions': {'typing_extensions'},
    'importlib-metadata': {'importlib_metadata'},
    'importlib-resources': {'importlib_resources'},
    'setuptools': {'setuptools', 'pkg_resources'},
    'ruamel.yaml': {'ruamel'},
    'email-validator': {'email_validator'},
    'newspaper3k': {'newspaper'},
    'docker-py': {'docker'},
    'psycopg2-binary': {'psycopg2'},
    'mysqlclient': {'MySQLdb'},
    'django-rest-framework': {'rest_framework'},
    'django-cors-headers': {'corsheaders'},
    'django-filter': {'django_filters'},
    'django-crispy-forms': {'crispy_forms'},
    'flask-cors': {'flask_cors'},
    'flask-login': {'flask_login'},
    'flask-sqlalchemy': {'flask_sqlalchemy'},
    'flask-wtf': {'flask_wtf'},
    'celery': {'celery'},
    'kombu': {'kombu'},
    'ujson': {'ujson'},
    'orjson': {'orjson'},
    'httpx': {'httpx'},
    'aiohttp': {'aiohttp'},
    'twisted': {'twisted'},
    'gevent': {'gevent'},
    'lxml': {'lxml'},
    'markupsafe': {'markupsafe'},
}

# npm packages where the import path differs from the package name,
# or where the package is consumed via config plugins rather than imports.
NPM_CONFIG_PACKAGES = {
    # Babel plugins/presets: referenced in babel.config.js, not imported
    'babel-plugin-module-resolver', 'babel-preset-expo',
    'babel-plugin-transform-remove-console',
    '@babel/core', '@babel/runtime', '@babel/preset-env',
    '@babel/preset-react', '@babel/preset-typescript',
    '@babel/plugin-proposal-decorators',
    # Expo config plugins: referenced in app.config.js/app.json
    'expo-build-properties', 'expo-dev-client', 'expo-system-ui',
    'expo-splash-screen', 'expo-updates', 'expo-tracking-transparency',
    # Metro/bundler config
    'react-native-svg-transformer', 'metro-react-native-babel-transformer',
    # TypeScript type packages: consumed by tsc, not imported in source
    # Note: any @types/* package is handled by the prefix check below,
    # but we list common ones explicitly for clarity
    '@types/react', '@types/react-native', '@types/node',
    '@types/react-dom', '@types/jest', '@types/mocha',
    '@types/react-native-vector-icons', '@types/fluent-ffmpeg',
    '@types/pdf-parse', '@types/uuid',
    # Test runners: invoked as CLI, not imported in source
    'jest', 'mocha', 'vitest', 'ts-jest', 'babel-jest',
    # Linters/formatters: invoked as CLI
    'eslint', 'prettier', 'eslint-config-google',
    'eslint-plugin-import', 'eslint-plugin-react',
    'eslint-plugin-react-hooks', 'eslint-plugin-jsx-a11y',
    # Build tools
    'typescript', 'webpack', 'vite', 'rollup', 'esbuild',
    'turbo', 'nx', 'lerna',
    # Package management utilities
    'patch-package', 'knip', 'depcheck', 'npm-check-updates', 'maestro',
    # React Native CLI
    '@react-native-community/cli',
    # React Native peer deps (required by navigation/router but not directly imported)
    'react-native-screens', 'react-native-safe-area-context',
    'react-native-gesture-handler',
}

# PyPI packages invoked as CLI tools via subprocess, not imported as modules
PYPI_CLI_PACKAGES = {
    'semgrep', 'black', 'isort', 'flake8', 'mypy', 'pylint',
    'bandit', 'safety', 'pip-audit', 'pyright', 'ruff',
    'pre-commit', 'tox', 'nox', 'poetry', 'pipenv',
    'gunicorn', 'uvicorn', 'hypercorn',
    'alembic', 'django', 'flask',
}

# Packages that are transitive dependencies (pulled in by other packages)
KNOWN_TRANSITIVE_DEPS = {
    'pypi': {'typing-extensions', 'importlib-metadata', 'importlib-resources',
             'setuptools', 'wheel', 'pip', 'certifi', 'charset-normalizer',
             'idna', 'urllib3', 'six', 'zipp', 'packaging'},
    'npm': {'tslib', 'regenerator-runtime', 'core-js', 'loose-envify',
            'object-assign', 'js-tokens', 'scheduler'},
}

# npm packages that are also used as Expo/RN peer dependencies
NPM_PEER_DEP_PACKAGES = {
    'react-native-screens', 'react-native-safe-area-context',
    'react-native-gesture-handler', 'react-native-reanimated',
    'react-native-svg', '@react-native-community/masked-view',
}


class PackageNameResolver:
    """
    Three-layer resolution of package name → importable module names.

    Layer 1: Local resolution: scan node_modules/ or site-packages .dist-info
    Layer 2: Registry resolution: PyPI JSON API, npm package.json main field
    Layer 3: Curated fallback: hardcoded table for known mismatches
    """

    def __init__(self, repo_path: str = '', ecosystem: str = ''):
        self._repo_path = repo_path
        self._ecosystem = ecosystem
        self._cache: dict[str, set[str]] = {}  # pkg_name → {import_names}
        self._config_refs: set[str] | None = None  # packages referenced in configs
        self._subprocess_refs: set[str] | None = None  # packages invoked via subprocess

    def get_import_names(self, package_name: str, ecosystem: str) -> set[str]:
        """Return the set of importable module names for a package."""
        cache_key = f"{ecosystem}:{package_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        names = set()

        # Layer 1: Local resolution
        local = self._resolve_local(package_name, ecosystem)
        if local:
            names.update(local)

        # Layer 2: Curated table (fast, no network: preferred over registry)
        if ecosystem == 'pypi':
            curated = PYPI_IMPORT_NAMES.get(package_name.lower())
            if curated:
                names.update(curated)

        # If no resolution found, default: derive from package name
        if not names:
            names = self._derive_default_names(package_name, ecosystem)

        self._cache[cache_key] = names
        return names

    def is_config_referenced(self, package_name: str) -> bool:
        """Check if a package is referenced in config/build files (not code imports)."""
        if self._config_refs is None:
            self._config_refs = self._scan_config_files()
        return package_name in self._config_refs

    def is_known_cli_tool(self, package_name: str, ecosystem: str) -> bool:
        """Check if a package is a CLI tool invoked via subprocess, not imported."""
        if ecosystem == 'pypi' and package_name.lower() in PYPI_CLI_PACKAGES:
            return True
        return False

    def is_known_config_package(self, package_name: str, ecosystem: str) -> bool:
        """Check if a package is known to be consumed via config, not imports."""
        if ecosystem == 'npm':
            if package_name in NPM_CONFIG_PACKAGES:
                return True
            # All @types/* packages are type definitions, not runtime imports
            if package_name.startswith('@types/'):
                return True
        return False

    def is_known_peer_dep(self, package_name: str, ecosystem: str) -> bool:
        """Check if a package is a known peer dependency."""
        if ecosystem == 'npm' and package_name in NPM_PEER_DEP_PACKAGES:
            return True
        return False

    def is_known_transitive(self, package_name: str, ecosystem: str) -> bool:
        """Check if a package is a known transitive dependency."""
        return package_name.lower() in KNOWN_TRANSITIVE_DEPS.get(ecosystem, set())

    def is_subprocess_invoked(self, package_name: str) -> bool:
        """Check if a package is invoked via subprocess in the codebase."""
        if self._subprocess_refs is None:
            self._subprocess_refs = self._scan_subprocess_calls()
        return package_name.lower() in self._subprocess_refs

    # ------------------------------------------------------------------
    # Layer 1: Local resolution
    # ------------------------------------------------------------------

    def _resolve_local(self, package_name: str, ecosystem: str) -> set[str]:
        """Resolve import names from local installed packages."""
        if not self._repo_path:
            return set()

        if ecosystem == 'npm':
            return self._resolve_local_npm(package_name)
        elif ecosystem == 'pypi':
            return self._resolve_local_pypi(package_name)
        return set()

    def _resolve_local_npm(self, package_name: str) -> set[str]:
        """Check node_modules/{pkg}/package.json for main/exports fields."""
        nm_path = os.path.join(self._repo_path, 'node_modules', package_name)
        pkg_json = os.path.join(nm_path, 'package.json')
        if not os.path.isfile(pkg_json):
            return set()
        try:
            with open(pkg_json, encoding='utf-8') as f:
                json.load(f)
            # If the package has exports with "." entry or main, it's importable
            # under its own name: no mismatch
            return set()  # npm packages generally import by package name
        except Exception:
            return set()

    def _resolve_local_pypi(self, package_name: str) -> set[str]:
        """Scan site-packages .dist-info/top_level.txt for real import names."""
        # Check common venv locations
        venv_dirs = [
            os.path.join(self._repo_path, '.venv'),
            os.path.join(self._repo_path, 'venv'),
            os.path.join(self._repo_path, 'env'),
        ]
        for venv in venv_dirs:
            if not os.path.isdir(venv):
                continue
            # Find site-packages
            for root, dirs, _files in os.walk(venv):
                if 'site-packages' in root:
                    return self._scan_dist_info(root, package_name)
                # Don't go too deep
                if root.count(os.sep) - venv.count(os.sep) > 4:
                    dirs.clear()
        return set()

    def _scan_dist_info(self, site_packages: str, package_name: str) -> set[str]:
        """Find top_level.txt in .dist-info directory."""
        # Normalize: python-dotenv → python_dotenv
        normalized = package_name.lower().replace('-', '_')
        try:
            for entry in os.listdir(site_packages):
                if entry.endswith('.dist-info'):
                    dist_name = entry.rsplit('-', 1)[0].lower().replace('-', '_')
                    if dist_name == normalized:
                        top_level = os.path.join(site_packages, entry, 'top_level.txt')
                        if os.path.isfile(top_level):
                            with open(top_level) as f:
                                modules = {line.strip() for line in f if line.strip()}
                            if modules:
                                return modules
        except Exception:
            pass
        return set()

    # ------------------------------------------------------------------
    # Config file scanning
    # ------------------------------------------------------------------

    def _scan_config_files(self) -> set[str]:
        """Scan config/build files for package name references."""
        if not self._repo_path:
            return set()

        config_patterns = [
            'app.config.js', 'app.config.ts', 'app.json',
            'babel.config.js', 'babel.config.json', '.babelrc',
            'metro.config.js', 'metro.config.ts',
            'webpack.config.js', 'webpack.config.ts',
            'vite.config.js', 'vite.config.ts',
            'rollup.config.js', 'rollup.config.ts',
            'tsconfig.json', 'jsconfig.json',
            '.eslintrc', '.eslintrc.js', '.eslintrc.json', 'eslint.config.js',
            '.prettierrc', '.prettierrc.js',
            'jest.config.js', 'jest.config.ts', 'jest.config.json',
            'vitest.config.js', 'vitest.config.ts',
            'tailwind.config.js', 'tailwind.config.ts',
            'postcss.config.js', 'next.config.js', 'nuxt.config.js',
            'setup.cfg', 'pyproject.toml', 'tox.ini', '.pre-commit-config.yaml',
        ]

        refs = set()
        for config_name in config_patterns:
            config_path = os.path.join(self._repo_path, config_name)
            if not os.path.isfile(config_path):
                continue
            try:
                with open(config_path, encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                # Extract package-like strings from config files
                # npm scoped: @scope/name
                for match in re.finditer(r'["\x27]((?:@[\w-]+/)?[\w][\w.-]*)["\x27]', content):
                    candidate = match.group(1)
                    # Filter out obvious non-package values
                    if (not candidate.startswith('.') and
                            not candidate.startswith('@/') and
                            '/' not in candidate.split('@')[-1].split('/')[0] if '@' not in candidate else True):
                        refs.add(candidate)
                        # Also add without /plugin suffix
                        if '/plugin' in candidate:
                            refs.add(candidate.split('/plugin')[0])
            except Exception:
                continue
        return refs

    # ------------------------------------------------------------------
    # Subprocess invocation scanning
    # ------------------------------------------------------------------

    def _scan_subprocess_calls(self) -> set[str]:
        """Scan Python source files for subprocess invocations of packages."""
        if not self._repo_path:
            return set()

        refs = set()
        skip_dirs = {'node_modules', '.git', 'vendor', '__pycache__', '.venv', 'venv',
                     'dist', 'build', '.cache', 'outputs'}

        for root, dirs, files in os.walk(self._repo_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if not fname.endswith('.py'):
                    continue
                full_path = os.path.join(root, fname)
                try:
                    with open(full_path, encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    # Match subprocess.run/call/Popen patterns
                    # subprocess.run(['semgrep', ...])
                    # subprocess.run('semgrep ...')
                    # os.system('semgrep ...')
                    for match in re.finditer(
                        r'(?:subprocess\.(?:run|call|check_call|check_output|Popen)|os\.system|os\.popen)\s*\(\s*'
                        r'(?:\[?\s*["\x27](\w[\w.-]*)["\x27])',
                        content
                    ):
                        refs.add(match.group(1).lower())
                    # Also match shutil.which('tool')
                    for match in re.finditer(r'shutil\.which\s*\(\s*["\x27](\w[\w.-]*)["\x27]', content):
                        refs.add(match.group(1).lower())
                except Exception:
                    continue
        return refs

    # ------------------------------------------------------------------
    # Default derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_default_names(package_name: str, ecosystem: str) -> set[str]:
        """Derive default import names when no resolution is available."""
        if ecosystem == 'pypi':
            # python-foo → python_foo AND foo (common pattern)
            base = package_name.lower().replace('-', '_')
            names = {base}
            # Also try without prefix: python-dateutil → dateutil
            if base.startswith('python_'):
                names.add(base[7:])
            return names
        elif ecosystem == 'npm':
            # npm packages import by their exact name
            return {package_name}
        elif ecosystem == 'cargo':
            # Rust crates: hyphen → underscore
            return {package_name.replace('-', '_')}
        elif ecosystem == 'go':
            return {package_name}
        else:
            return {package_name}


# ---------------------------------------------------------------------------
# Import-to-package name mapping
# ---------------------------------------------------------------------------

def extract_package_name_from_import(module: str, ecosystem: str) -> str:
    """
    Normalize an import path to a package name.

    Examples:
        flask.views       -> flask       (pypi)
        lodash/merge      -> lodash      (npm)
        @babel/core       -> @babel/core (npm, scoped)
        github.com/pkg/errors -> github.com/pkg/errors (go, full module)
        serde::Deserialize -> serde      (cargo)
    """
    if not module:
        return ''

    if ecosystem == 'npm':
        # Scoped packages: @scope/package/subpath -> @scope/package
        if module.startswith('@'):
            parts = module.split('/')
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
            return module
        # Regular: lodash/merge -> lodash
        return module.split('/')[0]

    if ecosystem == 'pypi':
        # flask.views -> flask, some_pkg.sub -> some_pkg
        # Also handle hyphenated package names (e.g., python-dateutil imported as dateutil)
        return module.split('.')[0].replace('-', '_')

    if ecosystem == 'go':
        # Go uses full module paths: github.com/pkg/errors
        return module

    if ecosystem == 'cargo':
        # Rust uses :: for paths: serde::Deserialize -> serde
        return module.split('::')[0]

    if ecosystem == 'packagist':
        # PHP namespaces: Vendor\Package\Class -> vendor/package
        return module.replace('\\', '/').split('/')[0]

    if ecosystem == 'maven':
        # Java: org.example.ClassName -> org.example (approximate)
        parts = module.split('.')
        if len(parts) > 2:
            return '.'.join(parts[:2])
        return module

    if ecosystem == 'rubygems':
        return module.split('/')[0].split('::')[0]

    # Default: first component
    return module.split('.')[0].split('/')[0]


# ---------------------------------------------------------------------------
# Core Analyzer
# ---------------------------------------------------------------------------

class DependencyCodePathAnalyzer:
    """
    Analyzes how dependencies are actually used in a codebase.

    Orchestration:
        1. Parse manifests → declared dependencies
        2. Map external_imports → package names
        3. Trace API call sites per dependency
        4. Compute depth scores
        5. Check registry health (cached, rate-limited)
        6. Classify remediation strategy
    """

    def __init__(self):
        self._registry_client = None
        self._name_resolver: PackageNameResolver | None = None

    @property
    def registry_client(self) -> PackageRegistryClient:
        if self._registry_client is None:
            from appsec_galaxy.config import REGISTRY_CACHE_TTL
            self._registry_client = PackageRegistryClient(cache_ttl=REGISTRY_CACHE_TTL)
        return self._registry_client

    def analyze(
        self,
        repo_path: str,
        cross_file_analyzer=None,
        trivy_findings: list[dict] | None = None,
    ) -> DependencyHealthReport:
        """
        Run full dependency code-path analysis.

        Args:
            repo_path: Path to repository root
            cross_file_analyzer: Optional CrossFileAnalyzer instance (reuses caches)
            trivy_findings: Optional Trivy findings to cross-reference CVEs
        """
        if not ENABLE_DEPENDENCY_ANALYSIS:
            return DependencyHealthReport(repo_path=repo_path)

        logger.info("📦 Starting dependency code-path analysis...")
        report = DependencyHealthReport(repo_path=repo_path)

        # Initialize the package name resolver for this repo
        self._name_resolver = PackageNameResolver(repo_path=repo_path)

        # 1. Discover and parse manifests
        declared_deps = self._discover_declared_deps(repo_path)
        report.total_dependencies = sum(len(v) for v in declared_deps.values())
        logger.info(f"Found {report.total_dependencies} declared dependencies across {len(declared_deps)} manifests")

        if report.total_dependencies == 0:
            return report

        # 2. Build usage map from external imports
        external_imports = {}
        if cross_file_analyzer and hasattr(cross_file_analyzer, 'external_imports'):
            external_imports = cross_file_analyzer.external_imports
        else:
            external_imports = self._scan_imports(repo_path)

        # 3. Build DependencyUsage for each declared dep
        usages: dict[str, DependencyUsage] = {}
        for manifest_file, deps in declared_deps.items():
            ecosystem = MANIFEST_TO_ECOSYSTEM.get(Path(manifest_file).name, 'unknown')
            for pkg_name, version_spec in deps.items():
                key = f"{ecosystem}:{pkg_name}"
                if key in usages:
                    continue

                usage = DependencyUsage(
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                    installed_version=version_spec,
                    manifest_file=manifest_file,
                )

                # Match imports to this package
                self._match_imports_to_package(usage, external_imports)

                # Trace API call sites
                if cross_file_analyzer:
                    self._trace_api_usage(usage, cross_file_analyzer)

                # Compute depth score
                self._compute_depth_score(usage)

                usages[key] = usage

        # 4. Check registry health (if enabled)
        if DEPENDENCY_HEALTH_CHECK:
            self._check_health_batch(usages)

        # 5. Cross-reference Trivy CVEs
        if trivy_findings:
            self._cross_reference_cves(usages, trivy_findings)

        # 6. Classify remediation strategy
        for usage in usages.values():
            self._classify_strategy(usage)

        # 7. Build report
        report.analyzed_dependencies = len(usages)
        report.dependencies = list(usages.values())

        for usage in usages.values():
            # Health breakdown
            report.health_breakdown[usage.health_status] = report.health_breakdown.get(usage.health_status, 0) + 1
            # Depth breakdown
            report.depth_breakdown[usage.depth_category] = report.depth_breakdown.get(usage.depth_category, 0) + 1
            # Strategy breakdown
            report.strategy_breakdown[usage.remediation_strategy] = report.strategy_breakdown.get(usage.remediation_strategy, 0) + 1

            if usage.remediation_strategy == 'inline':
                report.inline_candidates.append(usage)
            elif usage.remediation_strategy == 'remove':
                report.remove_candidates.append(usage)

        logger.info(
            f"✅ Dependency analysis complete: {report.analyzed_dependencies} deps analyzed, "
            f"strategies: {report.strategy_breakdown}"
        )
        return report

    # ------------------------------------------------------------------
    # Step 1: Manifest discovery
    # ------------------------------------------------------------------

    def _discover_declared_deps(self, repo_path: str) -> dict[str, dict[str, str]]:
        """Find and parse all manifest files in the repo."""
        results = {}
        Path(repo_path)

        manifest_names = {
            'package.json', 'requirements.txt', 'pyproject.toml', 'go.mod',
            'Cargo.toml', 'composer.json', 'pom.xml', 'build.gradle',
            'Gemfile', 'Pipfile',
        }
        skip_dirs = {'node_modules', '.git', 'vendor', '__pycache__', '.venv', 'venv',
                      'dist', 'build', '.cache', 'outputs'}

        for root, dirs, files in os.walk(repo_path):
            # Prune skip dirs
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if fname in manifest_names:
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, repo_path)
                    deps = ManifestParser.parse_manifest(full_path)
                    if deps:
                        results[rel_path] = deps
        return results

    # ------------------------------------------------------------------
    # Step 2: Import scanning (fallback when CrossFileAnalyzer unavailable)
    # ------------------------------------------------------------------

    def _scan_imports(self, repo_path: str) -> dict[str, list[dict]]:
        """Scan source files for import statements. Returns {module_name: [{file, line, imported_names}]}."""
        imports: dict[str, list[dict]] = {}
        skip_dirs = {'node_modules', '.git', 'vendor', '__pycache__', '.venv', 'venv',
                      'dist', 'build', '.cache', 'outputs'}
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.rb', '.php', '.java', '.kt', '.swift', '.css', '.scss', '.less'}

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                ext = Path(fname).suffix
                if ext not in extensions:
                    continue
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, repo_path)
                try:
                    with open(full_path, encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    file_imports = self._extract_imports(content, ext, rel_path)
                    for imp in file_imports:
                        module = imp['module']
                        if module not in imports:
                            imports[module] = []
                        imports[module].append(imp)
                except Exception:
                    continue
        return imports

    def _extract_imports(self, content: str, ext: str, file_path: str) -> list[dict]:
        """Extract import statements from source code."""
        results = []

        if ext == '.py':
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            results.append({
                                'module': alias.name,
                                'file': file_path,
                                'line': node.lineno,
                                'imported_names': [alias.asname or alias.name],
                            })
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            names = [a.name for a in node.names]
                            results.append({
                                'module': node.module,
                                'file': file_path,
                                'line': node.lineno,
                                'imported_names': names,
                            })
            except SyntaxError:
                pass

        elif ext in ('.js', '.ts', '.jsx', '.tsx'):
            # Strategy: extract all 'pkg-name' strings that appear in import contexts.
            # This handles static, dynamic, multiline, and re-export patterns.

            # 1. `from 'pkg'`: catches all patterns ending with `from 'pkg'`
            #    including multiline: `} from 'pkg'`, default+named: `import X, { Y } from 'pkg'`
            for match in re.finditer(r'''from\s+['"]([@\w/._-]+)['"]''', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                if not module.startswith('.'):
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

            # 2. `import 'pkg'`: side-effect imports (no `from`)
            for match in re.finditer(r'''import\s+['"]([@\w/._-]+)['"]''', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                if not module.startswith('.'):
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

            # 3. Dynamic imports: `import('pkg')` / `await import('pkg')`
            for match in re.finditer(r'''import\s*\(\s*['"]([@\w/._-]+)['"]\s*\)''', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                if not module.startswith('.'):
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

            # 4. require() calls
            for match in re.finditer(r'''require\s*\(\s*['"]([@\w/._-]+)['"]\s*\)''', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                if not module.startswith('.'):
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext == '.go':
            for match in re.finditer(r'"([^"]+)"', content):
                module = match.group(1)
                # Go external imports have a domain prefix
                if '.' in module.split('/')[0]:
                    line = content[:match.start()].count('\n') + 1
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext == '.rs':
            for match in re.finditer(r'(?:use|extern\s+crate)\s+(\w+)', content):
                module = match.group(1)
                if module not in ('std', 'core', 'alloc', 'self', 'super', 'crate'):
                    line = content[:match.start()].count('\n') + 1
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext == '.rb':
            for match in re.finditer(r"require\s+['\"]([^'\"]+)['\"]", content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext == '.php':
            for match in re.finditer(r'use\s+([\w\\]+)', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext == '.java' or ext == '.kt':
            for match in re.finditer(r'import\s+([\w.]+)', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext == '.swift':
            for match in re.finditer(r'import\s+(\w+)', content):
                module = match.group(1)
                if module not in ('Foundation', 'UIKit', 'SwiftUI', 'Combine', 'Darwin'):
                    line = content[:match.start()].count('\n') + 1
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        elif ext in ('.css', '.scss', '.less'):
            # CSS @import: @import "tailwindcss"; @import "tw-animate-css";
            for match in re.finditer(r'@import\s+["\x27]([@\w/._-]+)["\x27]', content):
                module = match.group(1)
                line = content[:match.start()].count('\n') + 1
                if not module.startswith('.') and not module.startswith('url('):
                    results.append({'module': module, 'file': file_path, 'line': line, 'imported_names': []})

        return results

    # ------------------------------------------------------------------
    # Step 3: Match imports to packages
    # ------------------------------------------------------------------

    def _match_imports_to_package(self, usage: DependencyUsage, external_imports: dict[str, list[dict]]):
        """Match external import entries to this package using three-layer name resolution."""
        pkg = usage.package_name
        ecosystem = usage.ecosystem

        # Get the set of importable module names for this package
        if self._name_resolver:
            known_import_names = self._name_resolver.get_import_names(pkg, ecosystem)
        else:
            known_import_names = {pkg.lower().replace('-', '_')}

        for module, import_list in external_imports.items():
            normalized = extract_package_name_from_import(module, ecosystem)

            # Check 1: Direct package name match (original logic)
            pkg_normalized = pkg.lower().replace('-', '_').replace('.', '_')
            norm_check = normalized.lower().replace('-', '_').replace('.', '_')
            direct_match = (pkg_normalized == norm_check or pkg.lower() == normalized.lower())

            # Check 2: Resolved import name match (new: handles python-dotenv→dotenv, etc.)
            import_root = module.split('.')[0].lower().replace('-', '_')
            resolved_match = any(
                import_root == known_name.lower().replace('-', '_').split('.')[0]
                for known_name in known_import_names
            )

            if direct_match or resolved_match:
                for imp in import_list:
                    usage.import_sites.append(imp)
                    usage.files_using.add(imp.get('file', ''))
                    for name in imp.get('imported_names', []):
                        usage.unique_apis_used.add(name)

    # ------------------------------------------------------------------
    # Step 4: Trace API usage with AST
    # ------------------------------------------------------------------

    def _trace_api_usage(self, usage: DependencyUsage, cross_file_analyzer):
        """Trace call sites using CrossFileAnalyzer's file analysis cache."""
        cache = getattr(cross_file_analyzer, 'file_analysis_cache', {})
        pkg_lower = usage.package_name.lower().replace('-', '_')

        # Get resolved import names for this package
        if self._name_resolver:
            known_names = {n.lower().replace('-', '_').split('.')[0]
                          for n in self._name_resolver.get_import_names(usage.package_name, usage.ecosystem)}
        else:
            known_names = {pkg_lower}

        for file_path, analysis in cache.items():
            # Check if this file imports the package
            imports = analysis.get('imports', [])
            file_imports_pkg = False
            imported_aliases = set()

            for imp in imports:
                mod = imp.get('module', '')
                normalized = extract_package_name_from_import(mod, usage.ecosystem)
                import_root = mod.split('.')[0].lower().replace('-', '_')
                if normalized.lower().replace('-', '_') == pkg_lower or import_root in known_names:
                    file_imports_pkg = True
                    # Track what names were imported
                    for name in imp.get('names', []):
                        imported_aliases.add(name)
                    # Also track module-level import (import flask -> flask.X)
                    imported_aliases.add(mod.split('.')[-1])

            if not file_imports_pkg:
                continue

            # Scan function calls in this file for the imported names
            functions = analysis.get('functions', [])
            for func in functions:
                func_name = func.get('name', '')
                # Check if any line in function body references our package's APIs
                if func_name and any(alias in func_name for alias in imported_aliases):
                    usage.call_sites.append({
                        'file': file_path,
                        'line': func.get('line', 0),
                        'function_called': func_name,
                        'context': 'function_definition',
                    })
                    usage.unique_apis_used.add(func_name)

    # ------------------------------------------------------------------
    # Step 5: Depth scoring
    # ------------------------------------------------------------------

    def _compute_depth_score(self, usage: DependencyUsage):
        """
        Compute embedding depth score (0.0 = trivial, 1.0 = deeply embedded).

        Weighted formula:
            - File spread:  min(files/10, 0.3)
            - API surface:  min(apis/5, 0.3)
            - Call frequency: min(calls/20, 0.2)
            - Deep patterns: 0.0 or 0.2 (subclassing, decorators, middleware)
        """
        file_count = len(usage.files_using)
        api_count = len(usage.unique_apis_used)
        call_count = len(usage.call_sites) + len(usage.import_sites)

        file_spread = min(file_count / 10.0, 0.3)
        api_surface = min(api_count / 5.0, 0.3)
        call_freq = min(call_count / 20.0, 0.2)

        # Check for deep integration patterns
        deep = 0.0
        deep_patterns = ['extends', 'implements', 'middleware', 'decorator', 'plugin', 'mixin']
        for site in usage.call_sites:
            ctx = site.get('context', '').lower()
            func = site.get('function_called', '').lower()
            if any(p in ctx or p in func for p in deep_patterns):
                deep = 0.2
                break

        score = file_spread + api_surface + call_freq + deep
        usage.depth_score = round(min(score, 1.0), 2)

        if usage.depth_score < 0.2:
            usage.depth_category = 'trivial'
        elif usage.depth_score < 0.4:
            usage.depth_category = 'shallow'
        elif usage.depth_score < 0.7:
            usage.depth_category = 'moderate'
        else:
            usage.depth_category = 'deep'

    # ------------------------------------------------------------------
    # Step 6: Registry health checks
    # ------------------------------------------------------------------

    def _check_health_batch(self, usages: dict[str, DependencyUsage]):
        """Check package health for all dependencies."""
        for _key, usage in usages.items():
            try:
                info = self.registry_client.check_package_health(
                    usage.package_name, usage.ecosystem, usage.installed_version
                )
                usage.health_status = info.health_status
                usage.health_info = {
                    'latest_version': info.latest_version,
                    'last_publish_date': info.last_publish_date or '',
                    'weekly_downloads': info.weekly_downloads,
                    'months_since_update': round(info.months_since_update, 1),
                    'deprecated': info.deprecated,
                }
            except Exception as e:
                logger.debug(f"Health check failed for {usage.package_name}: {e}")
                usage.health_status = 'unknown'

    # ------------------------------------------------------------------
    # Step 7: CVE cross-reference
    # ------------------------------------------------------------------

    def _cross_reference_cves(self, usages: dict[str, DependencyUsage], trivy_findings: list[dict]):
        """Match Trivy CVE findings to dependency usages."""
        for finding in trivy_findings:
            if finding.get('tool') != 'trivy':
                continue
            pkg_name = finding.get('package_name', '') or finding.get('extra', {}).get('metadata', {}).get('package_name', '')
            if not pkg_name:
                # Try extracting from message
                msg = finding.get('message', '') or finding.get('extra', {}).get('message', '')
                match = re.search(r'in\s+(\S+)', msg)
                if match:
                    pkg_name = match.group(1)
            if not pkg_name:
                continue

            # Find matching usage
            for _key, usage in usages.items():
                if pkg_name.lower() == usage.package_name.lower():
                    usage.has_cve = True
                    fixed = finding.get('fixed_version', '')
                    if fixed:
                        usage.fixed_version = fixed
                    if usage.health_status != 'dead':
                        usage.health_status = 'vulnerable'
                    break

    # ------------------------------------------------------------------
    # Step 8: Strategy classification
    # ------------------------------------------------------------------

    def _classify_strategy(self, usage: DependencyUsage):
        """
        Decision tree for remediation strategy:
            0. No imports BUT known config/CLI/peer/transitive → keep (not a false positive)
            1. No call sites at all → remove
            2. Has CVE + fixed version → upgrade
            3. Trivial + (stale/abandoned) → inline
            4. Shallow + known replacement → replace
            5. Healthy + no CVEs → keep
            6. Otherwise → keep (with notes)
        """
        # 1. No usage at all: but check for false positive patterns first
        if not usage.import_sites and not usage.call_sites and not usage.files_using:
            # Check if this package is used in ways we can't detect via imports
            if self._name_resolver:
                pkg = usage.package_name
                eco = usage.ecosystem

                # Config/build tool packages (babel, eslint, types, etc.)
                if self._name_resolver.is_known_config_package(pkg, eco):
                    usage.remediation_strategy = 'keep'
                    usage.replacement_suggestion = 'config/build tool: no code imports expected'
                    return

                # CLI tools invoked via subprocess
                if self._name_resolver.is_known_cli_tool(pkg, eco):
                    usage.remediation_strategy = 'keep'
                    usage.replacement_suggestion = 'CLI tool: invoked via subprocess, not imported'
                    return

                # Actually invoked via subprocess in this codebase
                if self._name_resolver.is_subprocess_invoked(pkg):
                    usage.remediation_strategy = 'keep'
                    usage.replacement_suggestion = 'invoked via subprocess in source code'
                    return

                # Referenced in config files
                if self._name_resolver.is_config_referenced(pkg):
                    usage.remediation_strategy = 'keep'
                    usage.replacement_suggestion = 'referenced in config/build files'
                    return

                # Known peer dependency
                if self._name_resolver.is_known_peer_dep(pkg, eco):
                    usage.remediation_strategy = 'keep'
                    usage.replacement_suggestion = 'peer dependency: required by other packages'
                    return

                # Known transitive dependency
                if self._name_resolver.is_known_transitive(pkg, eco):
                    usage.remediation_strategy = 'keep'
                    usage.replacement_suggestion = 'transitive dependency: required by other packages'
                    return

            usage.remediation_strategy = 'remove'
            return

        # 2. Has CVE with fix available
        if usage.has_cve and usage.fixed_version:
            usage.remediation_strategy = 'upgrade'
            return

        # 3. Trivial + stale/abandoned → inline
        if (usage.depth_score < DEPENDENCY_INLINE_THRESHOLD and
                usage.health_status in ('stale', 'abandoned', 'dead')):
            usage.remediation_strategy = 'inline'
            if usage.package_name in KNOWN_REPLACEMENTS:
                usage.replacement_suggestion = KNOWN_REPLACEMENTS[usage.package_name]
            return

        # 4. Shallow + known replacement
        if usage.depth_category in ('trivial', 'shallow') and usage.package_name in KNOWN_REPLACEMENTS:
            usage.remediation_strategy = 'replace'
            usage.replacement_suggestion = KNOWN_REPLACEMENTS[usage.package_name]
            return

        # 5. Has CVE but no fix
        if usage.has_cve:
            # Check for known replacement
            if usage.package_name in KNOWN_REPLACEMENTS:
                usage.remediation_strategy = 'replace'
                usage.replacement_suggestion = KNOWN_REPLACEMENTS[usage.package_name]
            else:
                usage.remediation_strategy = 'upgrade'
            return

        # 6. Healthy, no issues
        usage.remediation_strategy = 'keep'


# ---------------------------------------------------------------------------
# Convenience function for integration
# ---------------------------------------------------------------------------

def run_dependency_analysis(
    repo_path: str,
    cross_file_analyzer=None,
    trivy_findings: list[dict] | None = None,
) -> DependencyHealthReport | None:
    """
    Run dependency code-path analysis. Returns None if feature is disabled.

    This is the main entry point for integration with main.py / web_app.py.
    """
    if not ENABLE_DEPENDENCY_ANALYSIS:
        return None

    try:
        analyzer = DependencyCodePathAnalyzer()
        return analyzer.analyze(repo_path, cross_file_analyzer, trivy_findings)
    except Exception as e:
        logger.error(f"Dependency analysis failed: {e}")
        return None
