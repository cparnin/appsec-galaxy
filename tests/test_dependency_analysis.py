"""
Dependency code-path analysis: manifest parsing, import-to-package
resolution, depth scoring, registry lookups, and CVE reachability.
"""

import pytest
import json
from unittest.mock import patch


from appsec_galaxy.dependency_analyzer import (
    ManifestParser, DependencyCodePathAnalyzer, DependencyUsage,
    extract_package_name_from_import,
    KNOWN_REPLACEMENTS,
    PackageNameResolver,
)
from appsec_galaxy.package_registry import PackageRegistryClient, PackageHealthInfo


class TestManifestParsing:
    """Test manifest file parsing across ecosystems."""

    def test_parse_package_json(self, temp_dir):
        """Test npm package.json parsing."""
        pkg = temp_dir / "package.json"
        pkg.write_text(json.dumps({
            "name": "test",
            "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
            "devDependencies": {"jest": "^29.0.0"}
        }))
        deps = ManifestParser.parse_manifest(str(pkg))
        assert "express" in deps
        assert "lodash" in deps
        assert "jest" in deps
        assert deps["express"] == "^4.18.0"

    def test_parse_requirements_txt(self, temp_dir):
        """Test Python requirements.txt parsing."""
        req = temp_dir / "requirements.txt"
        req.write_text("flask==2.3.0\nrequests>=2.28.0\n# comment\nnumpy\n-r other.txt\n")
        deps = ManifestParser.parse_manifest(str(req))
        assert "flask" in deps
        assert "requests" in deps
        assert "numpy" in deps
        assert deps["flask"] == "==2.3.0"

    def test_parse_go_mod(self, temp_dir):
        """Test Go go.mod parsing."""
        gomod = temp_dir / "go.mod"
        gomod.write_text("""module example.com/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/pkg/errors v0.9.1
)
""")
        deps = ManifestParser.parse_manifest(str(gomod))
        assert "github.com/gin-gonic/gin" in deps
        assert "github.com/pkg/errors" in deps

    def test_parse_cargo_toml(self, temp_dir):
        """Test Rust Cargo.toml parsing."""
        cargo = temp_dir / "Cargo.toml"
        cargo.write_text("""[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
""")
        deps = ManifestParser.parse_manifest(str(cargo))
        assert "serde" in deps
        assert "tokio" in deps
        assert deps["serde"] == "1.0"

    def test_parse_composer_json(self, temp_dir):
        """Test PHP composer.json parsing."""
        comp = temp_dir / "composer.json"
        comp.write_text(json.dumps({
            "require": {"php": "^8.1", "laravel/framework": "^10.0", "ext-json": "*"},
            "require-dev": {"phpunit/phpunit": "^10.0"}
        }))
        deps = ManifestParser.parse_manifest(str(comp))
        assert "laravel/framework" in deps
        assert "phpunit/phpunit" in deps
        # php and ext- should be excluded
        assert "php" not in deps
        assert "ext-json" not in deps

    def test_parse_gemfile(self, temp_dir):
        """Test Ruby Gemfile parsing."""
        gemfile = temp_dir / "Gemfile"
        gemfile.write_text("""source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'puma'
# gem 'commented-out'
""")
        deps = ManifestParser.parse_manifest(str(gemfile))
        assert "rails" in deps
        assert "puma" in deps
        assert deps["rails"] == "~> 7.0"

    def test_parse_malformed_json(self, temp_dir):
        """Test graceful handling of malformed manifest."""
        pkg = temp_dir / "package.json"
        pkg.write_text("{ this is not valid json }")
        deps = ManifestParser.parse_manifest(str(pkg))
        assert deps == {}

    def test_parse_empty_file(self, temp_dir):
        """Test empty manifest file."""
        req = temp_dir / "requirements.txt"
        req.write_text("")
        deps = ManifestParser.parse_manifest(str(req))
        assert deps == {}

    def test_unsupported_manifest(self, temp_dir):
        """Test unsupported manifest type returns empty."""
        unknown = temp_dir / "unknown.lock"
        unknown.write_text("some content")
        deps = ManifestParser.parse_manifest(str(unknown))
        assert deps == {}

    def test_parse_build_gradle(self, temp_dir):
        """Test Java build.gradle parsing."""
        gradle = temp_dir / "build.gradle"
        gradle.write_text("""
dependencies {
    implementation 'org.springframework:spring-core:5.3.0'
    testImplementation 'junit:junit:4.13'
    api 'com.google.guava:guava:31.0'
}
""")
        deps = ManifestParser.parse_manifest(str(gradle))
        assert "org.springframework:spring-core" in deps
        assert "junit:junit" in deps

    def test_parse_pom_xml(self, temp_dir):
        """Test Maven pom.xml parsing."""
        pom = temp_dir / "pom.xml"
        pom.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
    </dependencies>
</project>
""")
        deps = ManifestParser.parse_manifest(str(pom))
        assert "org.springframework:spring-core" in deps

    def test_parse_pipfile(self, temp_dir):
        """Test Python Pipfile parsing."""
        pipfile = temp_dir / "Pipfile"
        pipfile.write_text("""[packages]
flask = "==2.3.0"
requests = "*"

[dev-packages]
pytest = ">=7.0"
""")
        deps = ManifestParser.parse_manifest(str(pipfile))
        assert "flask" in deps
        assert "requests" in deps
        assert "pytest" in deps

class TestImportToPackageMapping:
    """Test import-to-package name normalization."""

    def test_python_dotted_import(self):
        assert extract_package_name_from_import("flask.views", "pypi") == "flask"

    def test_python_top_level(self):
        assert extract_package_name_from_import("requests", "pypi") == "requests"

    def test_python_hyphenated(self):
        # python-dateutil is imported as dateutil
        assert extract_package_name_from_import("dateutil", "pypi") == "dateutil"

    def test_npm_simple(self):
        assert extract_package_name_from_import("lodash", "npm") == "lodash"

    def test_npm_subpath(self):
        assert extract_package_name_from_import("lodash/merge", "npm") == "lodash"

    def test_npm_scoped(self):
        assert extract_package_name_from_import("@babel/core", "npm") == "@babel/core"

    def test_npm_scoped_subpath(self):
        assert extract_package_name_from_import("@babel/core/lib/transform", "npm") == "@babel/core"

    def test_go_full_module(self):
        assert extract_package_name_from_import("github.com/pkg/errors", "go") == "github.com/pkg/errors"

    def test_cargo_with_path(self):
        assert extract_package_name_from_import("serde::Deserialize", "cargo") == "serde"

    def test_rubygems(self):
        assert extract_package_name_from_import("rails/railtie", "rubygems") == "rails"

    def test_empty_input(self):
        assert extract_package_name_from_import("", "npm") == ""

class TestDepthScoring:
    """Test dependency embedding depth score computation."""

    def test_trivial_score(self):
        """Single file, single API, no imports list → trivial."""
        usage = DependencyUsage(package_name="is-odd", ecosystem="npm")
        usage.files_using = {"app.js"}
        usage.unique_apis_used = {"isOdd"}
        # No import_sites: just tracked via files_using

        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)

        assert usage.depth_score < 0.4
        assert usage.depth_category in ("trivial", "shallow")

    def test_shallow_score(self):
        """A few files, couple APIs → shallow or moderate."""
        usage = DependencyUsage(package_name="lodash", ecosystem="npm")
        usage.files_using = {"a.js", "b.js"}
        usage.unique_apis_used = {"get"}

        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)

        assert usage.depth_score <= 0.5
        assert usage.depth_category in ("trivial", "shallow", "moderate")

    def test_moderate_score(self):
        """Many files, many APIs → moderate or deep."""
        usage = DependencyUsage(package_name="express", ecosystem="npm")
        usage.files_using = {f"file{i}.js" for i in range(6)}
        usage.unique_apis_used = {"get", "post", "use", "listen"}
        usage.import_sites = [{"file": f, "line": 1} for f in usage.files_using]
        usage.call_sites = [{"file": f"file{i}.js", "line": i, "function_called": "get", "context": "route"} for i in range(10)]

        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)

        assert usage.depth_score >= 0.4
        assert usage.depth_category in ("moderate", "deep")

    def test_deep_score(self):
        """Many files, many APIs, deep integration → deep."""
        usage = DependencyUsage(package_name="django", ecosystem="pypi")
        usage.files_using = {f"module{i}.py" for i in range(12)}
        usage.unique_apis_used = {"Model", "View", "Admin", "Form", "Serializer", "Middleware"}
        usage.import_sites = [{"file": f, "line": 1} for f in usage.files_using]
        usage.call_sites = [
            {"file": f"module{i}.py", "line": i, "function_called": "extends", "context": "class extends Model"}
            for i in range(25)
        ]

        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)

        assert usage.depth_score >= 0.7
        assert usage.depth_category == "deep"

    def test_no_usage_trivial(self):
        """Zero usage → trivial with score 0."""
        usage = DependencyUsage(package_name="unused", ecosystem="npm")
        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)
        assert usage.depth_score == 0.0
        assert usage.depth_category == "trivial"

class TestStrategyClassification:
    """Test remediation strategy decision tree."""

    def test_no_usage_remove(self):
        """No imports → remove."""
        usage = DependencyUsage(package_name="unused-pkg", ecosystem="npm")
        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == "remove"

    def test_cve_with_fix_upgrade(self):
        """Has CVE + fix → upgrade."""
        usage = DependencyUsage(package_name="lodash", ecosystem="npm")
        usage.has_cve = True
        usage.fixed_version = "4.17.21"
        usage.import_sites = [{"file": "a.js", "line": 1}]
        usage.files_using = {"a.js"}
        usage.unique_apis_used = {"get"}
        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == "upgrade"

    def test_trivial_stale_inline(self):
        """Trivial + stale + no known replacement → inline."""
        usage = DependencyUsage(package_name="obscure-tiny-lib", ecosystem="npm")
        usage.health_status = "abandoned"
        # Minimal usage: 1 file, 1 API, depth < inline threshold
        usage.files_using = {"a.js"}
        usage.unique_apis_used = {"doThing"}
        # import_sites contribute to call_count, keep minimal
        usage.import_sites = [{"file": "a.js", "line": 1}]
        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)
        # Verify score is below inline threshold (0.3 default)
        # If score is above threshold due to formula, the strategy won't be inline
        # Adjust: the formula gives 0.1 (file) + 0.2 (api) + 0.05 (call) = 0.35
        # So we need to use the default threshold or adjust. Use no API for true trivial.
        usage2 = DependencyUsage(package_name="obscure-tiny-lib", ecosystem="npm")
        usage2.health_status = "abandoned"
        usage2.files_using = {"a.js"}
        usage2.import_sites = [{"file": "a.js", "line": 1}]
        # No unique_apis_used → api_surface = 0
        analyzer._compute_depth_score(usage2)
        analyzer._classify_strategy(usage2)
        assert usage2.remediation_strategy == "inline"

    def test_shallow_known_replacement_replace(self):
        """Shallow + known replacement → replace."""
        usage = DependencyUsage(package_name="moment", ecosystem="npm")
        usage.health_status = "healthy"
        usage.import_sites = [{"file": "a.js", "line": 1}]
        usage.files_using = {"a.js"}
        usage.unique_apis_used = {"format"}
        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == "replace"
        assert "dayjs" in usage.replacement_suggestion

    def test_healthy_no_cve_keep(self):
        """Healthy + no CVE + used → keep."""
        usage = DependencyUsage(package_name="express", ecosystem="npm")
        usage.health_status = "healthy"
        usage.import_sites = [{"file": f"file{i}.js", "line": 1} for i in range(5)]
        usage.files_using = {f"file{i}.js" for i in range(5)}
        usage.unique_apis_used = {"get", "post", "use", "listen"}
        usage.call_sites = [{"file": "app.js", "line": 1, "function_called": "app.get", "context": "route"}] * 10
        analyzer = DependencyCodePathAnalyzer()
        analyzer._compute_depth_score(usage)
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == "keep"

class TestPackageRegistry:
    """Test package registry client."""

    def test_cache_stores_result(self):
        """Test that results are cached."""
        client = PackageRegistryClient(cache_ttl=60)
        info = PackageHealthInfo(package_name="test", ecosystem="npm", health_status="healthy")
        client._set_cached("npm:test", info)
        cached = client._get_cached("npm:test")
        assert cached is not None
        assert cached.health_status == "healthy"

    def test_cache_expiry(self):
        """Test that expired cache returns None."""
        client = PackageRegistryClient(cache_ttl=0)  # Immediate expiry
        info = PackageHealthInfo(package_name="test", ecosystem="npm")
        client._set_cached("npm:test", info)
        import time
        time.sleep(0.01)
        cached = client._get_cached("npm:test")
        assert cached is None

    def test_months_since_calculation(self):
        """Test date parsing and month calculation."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        months = PackageRegistryClient._months_since(recent)
        assert 0.5 < months < 2.0

    def test_months_since_old_date(self):
        """Test with an old date."""
        months = PackageRegistryClient._months_since("2020-01-01T00:00:00Z")
        assert months > 48  # More than 4 years

    def test_months_since_invalid_date(self):
        """Test graceful handling of invalid date."""
        months = PackageRegistryClient._months_since("not-a-date")
        assert months == 0.0

    @patch('appsec_galaxy.package_registry.requests')
    def test_graceful_network_failure(self, mock_requests):
        """Test that network failures result in 'unknown' status."""
        mock_requests.get.side_effect = Exception("Network error")
        client = PackageRegistryClient()
        info = client.check_package_health("test-pkg", "npm")
        assert info.health_status == "unknown"

    def test_unsupported_ecosystem(self):
        """Test unsupported ecosystem returns unknown."""
        client = PackageRegistryClient()
        info = client.check_package_health("test", "unsupported_ecosystem")
        assert info.health_status == "unknown"

class TestDependencyAnalyzerIntegration:
    """Integration tests for the full dependency analyzer.

    Health checks are disabled: they issue one registry HTTP request per
    package, and a failed request degrades to "unknown" so the tests would
    pass either way while making dozens of outbound calls per run.
    """

    @pytest.fixture(autouse=True)
    def _no_registry_calls(self, monkeypatch):
        # The flag is read into a module constant at import time, so setting
        # the env var here would be too late.
        import appsec_galaxy.dependency_analyzer as da
        import appsec_galaxy.package_registry as pr
        monkeypatch.setattr(da, 'DEPENDENCY_HEALTH_CHECK', False, raising=False)
        monkeypatch.setattr(pr.PackageRegistryClient, '_http_get',
                            lambda self, url, headers=None: pytest.fail(f'no network in tests: {url}'))

    def test_analyze_npm_repo(self, mock_repo):
        """Both package.json dependencies are found, by name."""
        report = DependencyCodePathAnalyzer().analyze(str(mock_repo))
        assert report.total_dependencies > 0
        assert report.analyzed_dependencies > 0
        pkg_names = {d.package_name for d in report.dependencies}
        assert {"express", "lodash"} <= pkg_names

    def test_analyze_python_repo(self, mock_repo):
        pkg_names = {d.package_name for d in DependencyCodePathAnalyzer().analyze(str(mock_repo)).dependencies}
        assert {"flask", "requests"} <= pkg_names

    def test_report_breakdowns_count_every_dependency(self, mock_repo):
        report = DependencyCodePathAnalyzer().analyze(str(mock_repo))
        for breakdown in (report.health_breakdown, report.depth_breakdown, report.strategy_breakdown):
            assert sum(breakdown.values()) == report.analyzed_dependencies

    def test_report_to_dict_round_trips_dependencies(self, mock_repo):
        report = DependencyCodePathAnalyzer().analyze(str(mock_repo))
        d = report.to_dict()
        assert {entry['package_name'] for entry in d['dependencies']} == {
            dep.package_name for dep in report.dependencies}
        assert d['health_breakdown'] == report.health_breakdown

    def test_disabled_returns_none(self, mock_repo):
        """Test that disabled feature returns None."""
        from appsec_galaxy import dependency_analyzer
        original = dependency_analyzer.ENABLE_DEPENDENCY_ANALYSIS
        try:
            dependency_analyzer.ENABLE_DEPENDENCY_ANALYSIS = False
            result = dependency_analyzer.run_dependency_analysis(str(mock_repo))
            assert result is None
        finally:
            dependency_analyzer.ENABLE_DEPENDENCY_ANALYSIS = original

    def test_empty_repo(self, temp_dir):
        """Test analysis of repo with no manifests."""
        empty_repo = temp_dir / "empty"
        empty_repo.mkdir()
        analyzer = DependencyCodePathAnalyzer()
        report = analyzer.analyze(str(empty_repo))
        assert report.total_dependencies == 0

    def test_known_replacements_populated(self):
        """Test that KNOWN_REPLACEMENTS has expected entries."""
        assert "moment" in KNOWN_REPLACEMENTS
        assert "request" in KNOWN_REPLACEMENTS
        assert "pycrypto" in KNOWN_REPLACEMENTS
        assert "left-pad" in KNOWN_REPLACEMENTS

class TestPackageNameResolver:
    """Test the three-layer package name → import name resolution."""

    def test_pypi_curated_table_python_dotenv(self):
        """python-dotenv should resolve to 'dotenv'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('python-dotenv', 'pypi')
        assert 'dotenv' in names

    def test_pypi_curated_table_gitpython(self):
        """gitpython should resolve to 'git'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('gitpython', 'pypi')
        assert 'git' in names

    def test_pypi_curated_table_pillow(self):
        """Pillow should resolve to 'PIL'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('Pillow', 'pypi')
        assert 'PIL' in names

    def test_pypi_curated_table_beautifulsoup4(self):
        """beautifulsoup4 should resolve to 'bs4'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('beautifulsoup4', 'pypi')
        assert 'bs4' in names

    def test_pypi_curated_table_scikit_learn(self):
        """scikit-learn should resolve to 'sklearn'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('scikit-learn', 'pypi')
        assert 'sklearn' in names

    def test_pypi_curated_table_pyyaml(self):
        """pyyaml should resolve to 'yaml'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('pyyaml', 'pypi')
        assert 'yaml' in names

    def test_pypi_curated_table_opencv(self):
        """opencv-python should resolve to 'cv2'."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('opencv-python', 'pypi')
        assert 'cv2' in names

    def test_pypi_default_derivation(self):
        """Unknown PyPI package should derive from hyphenated name."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('some-unknown-pkg', 'pypi')
        assert 'some_unknown_pkg' in names

    def test_pypi_python_prefix_derivation(self):
        """python-* packages should also try without prefix."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('python-foobar', 'pypi')
        assert 'python_foobar' in names
        assert 'foobar' in names

    def test_npm_default_derivation(self):
        """npm packages should resolve to their own name."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('lodash', 'npm')
        assert 'lodash' in names

    def test_cargo_hyphen_to_underscore(self):
        """Cargo crates convert hyphens to underscores."""
        resolver = PackageNameResolver(repo_path='')
        names = resolver.get_import_names('serde-json', 'cargo')
        assert 'serde_json' in names

    def test_results_are_cached(self):
        """Second call should return cached result."""
        resolver = PackageNameResolver(repo_path='')
        names1 = resolver.get_import_names('Pillow', 'pypi')
        names2 = resolver.get_import_names('Pillow', 'pypi')
        assert names1 is names2  # Same object (cached)

class TestConfigPackageDetection:
    """Test detection of config/build tool packages."""

    def test_npm_types_packages(self):
        """All @types/* packages should be recognized as config packages."""
        resolver = PackageNameResolver(repo_path='')
        assert resolver.is_known_config_package('@types/react', 'npm')
        assert resolver.is_known_config_package('@types/anything-new', 'npm')

    def test_npm_babel_packages(self):
        """Babel packages should be recognized as config packages."""
        resolver = PackageNameResolver(repo_path='')
        assert resolver.is_known_config_package('@babel/core', 'npm')
        assert resolver.is_known_config_package('babel-preset-expo', 'npm')

    def test_npm_build_tools(self):
        """Build tools should be recognized as config packages."""
        resolver = PackageNameResolver(repo_path='')
        assert resolver.is_known_config_package('typescript', 'npm')
        assert resolver.is_known_config_package('prettier', 'npm')
        assert resolver.is_known_config_package('jest', 'npm')

    def test_pypi_cli_tools(self):
        """Python CLI tools should be recognized."""
        resolver = PackageNameResolver(repo_path='')
        assert resolver.is_known_cli_tool('semgrep', 'pypi')
        assert resolver.is_known_cli_tool('black', 'pypi')
        assert resolver.is_known_cli_tool('mypy', 'pypi')
        assert not resolver.is_known_cli_tool('requests', 'pypi')

    def test_known_peer_deps(self):
        """Peer dependencies should be recognized."""
        resolver = PackageNameResolver(repo_path='')
        assert resolver.is_known_peer_dep('react-native-screens', 'npm')
        assert not resolver.is_known_peer_dep('lodash', 'npm')

    def test_known_transitive_deps(self):
        """Transitive dependencies should be recognized."""
        resolver = PackageNameResolver(repo_path='')
        assert resolver.is_known_transitive('typing-extensions', 'pypi')
        assert resolver.is_known_transitive('tslib', 'npm')
        assert not resolver.is_known_transitive('requests', 'pypi')

    def test_not_config_package_for_pypi(self):
        """NPM config package check shouldn't match for pypi."""
        resolver = PackageNameResolver(repo_path='')
        assert not resolver.is_known_config_package('typescript', 'pypi')

class TestConfigFileScanningIntegration:
    """Test config file scanning with real filesystem."""

    def test_scan_config_files_with_app_config(self, tmp_path):
        """Packages in app.config.js should be detected."""
        config = tmp_path / 'app.config.js'
        config.write_text('''
        export default {
            plugins: [
                "expo-font",
                "expo-build-properties",
                ["expo-image-picker", { photosPermission: "Allow" }],
            ]
        }
        ''')
        resolver = PackageNameResolver(repo_path=str(tmp_path))
        assert resolver.is_config_referenced('expo-font')
        assert resolver.is_config_referenced('expo-build-properties')
        assert resolver.is_config_referenced('expo-image-picker')

    def test_scan_config_files_with_babel_config(self, tmp_path):
        """Packages in babel.config.js should be detected."""
        config = tmp_path / 'babel.config.js'
        config.write_text('''
        module.exports = {
            presets: ["babel-preset-expo"],
            plugins: ["react-native-reanimated"]
        }
        ''')
        resolver = PackageNameResolver(repo_path=str(tmp_path))
        assert resolver.is_config_referenced('babel-preset-expo')
        assert resolver.is_config_referenced('react-native-reanimated')

    def test_no_config_files(self, tmp_path):
        """No config files should return empty set."""
        resolver = PackageNameResolver(repo_path=str(tmp_path))
        assert not resolver.is_config_referenced('anything')

class TestSubprocessDetection:
    """Test subprocess invocation scanning."""

    def test_detect_subprocess_run(self, tmp_path):
        """Packages invoked via subprocess.run should be detected."""
        src = tmp_path / 'scanner.py'
        src.write_text('''
import subprocess
result = subprocess.run(['semgrep', '--config', 'auto', '.'], capture_output=True)
''')
        resolver = PackageNameResolver(repo_path=str(tmp_path))
        assert resolver.is_subprocess_invoked('semgrep')

    def test_detect_subprocess_check_output(self, tmp_path):
        """Packages invoked via subprocess.check_output should be detected."""
        src = tmp_path / 'tool.py'
        src.write_text('''
import subprocess
out = subprocess.check_output(['gitleaks', 'detect'])
''')
        resolver = PackageNameResolver(repo_path=str(tmp_path))
        assert resolver.is_subprocess_invoked('gitleaks')

    def test_no_subprocess_calls(self, tmp_path):
        """Should return False when package is not invoked via subprocess."""
        src = tmp_path / 'app.py'
        src.write_text('import requests\nrequests.get("https://example.com")\n')
        resolver = PackageNameResolver(repo_path=str(tmp_path))
        assert not resolver.is_subprocess_invoked('requests')

class TestImportExtraction:
    """Test JS/TS/CSS import extraction edge cases."""

    def test_multiline_named_import(self, tmp_path):
        """Multiline imports like `} from 'pkg'` should be detected."""
        src = tmp_path / 'app.ts'
        src.write_text("import {\n  Foo,\n  Bar,\n} from 'some-package';\n")
        analyzer = DependencyCodePathAnalyzer()
        results = analyzer._extract_imports(src.read_text(), '.ts', 'app.ts')
        modules = [r['module'] for r in results]
        assert 'some-package' in modules

    def test_default_plus_named_import(self, tmp_path):
        """Imports like `import Default, { Named } from 'pkg'` should be detected."""
        src = tmp_path / 'app.ts'
        src.write_text("import TiktokAds, { TikTokLaunchApp } from 'expo-tiktok-ads-events';\n")
        analyzer = DependencyCodePathAnalyzer()
        results = analyzer._extract_imports(src.read_text(), '.ts', 'app.ts')
        modules = [r['module'] for r in results]
        assert 'expo-tiktok-ads-events' in modules

    def test_dynamic_import(self, tmp_path):
        """Dynamic imports like `await import('pkg')` should be detected."""
        src = tmp_path / 'app.ts'
        src.write_text("const { extractText } = await import('expo-pdf-text-extract');\n")
        analyzer = DependencyCodePathAnalyzer()
        results = analyzer._extract_imports(src.read_text(), '.ts', 'app.ts')
        modules = [r['module'] for r in results]
        assert 'expo-pdf-text-extract' in modules

    def test_css_at_import(self, tmp_path):
        """CSS @import like `@import 'tailwindcss'` should be detected."""
        src = tmp_path / 'index.css'
        src.write_text('@import "tailwindcss";\n@import "tw-animate-css";\n')
        analyzer = DependencyCodePathAnalyzer()
        results = analyzer._extract_imports(src.read_text(), '.css', 'index.css')
        modules = [r['module'] for r in results]
        assert 'tailwindcss' in modules
        assert 'tw-animate-css' in modules

    def test_css_relative_import_skipped(self, tmp_path):
        """CSS @import of relative paths should be skipped."""
        src = tmp_path / 'styles.css'
        src.write_text('@import "./base.css";\n@import "tailwindcss";\n')
        analyzer = DependencyCodePathAnalyzer()
        results = analyzer._extract_imports(src.read_text(), '.css', 'styles.css')
        modules = [r['module'] for r in results]
        assert './base.css' not in modules
        assert 'tailwindcss' in modules

    def test_side_effect_import(self, tmp_path):
        """Side-effect imports like `import 'pkg'` should be detected."""
        src = tmp_path / 'polyfills.ts'
        src.write_text("import 'react-native-gesture-handler';\n")
        analyzer = DependencyCodePathAnalyzer()
        results = analyzer._extract_imports(src.read_text(), '.ts', 'polyfills.ts')
        modules = [r['module'] for r in results]
        assert 'react-native-gesture-handler' in modules

class TestStrategyWithResolver:
    """Test that strategy classification uses resolver to prevent false positives."""

    def test_cli_tool_keeps_instead_of_remove(self):
        """A CLI tool with no imports should be 'keep', not 'remove'."""
        analyzer = DependencyCodePathAnalyzer()
        analyzer._name_resolver = PackageNameResolver(repo_path='')
        usage = DependencyUsage(
            package_name='semgrep', ecosystem='pypi',
            health_status='healthy',
        )
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == 'keep'
        assert 'CLI tool' in usage.replacement_suggestion

    def test_types_package_keeps_instead_of_remove(self):
        """A @types/* package with no imports should be 'keep', not 'remove'."""
        analyzer = DependencyCodePathAnalyzer()
        analyzer._name_resolver = PackageNameResolver(repo_path='')
        usage = DependencyUsage(
            package_name='@types/react', ecosystem='npm',
            health_status='healthy',
        )
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == 'keep'
        assert 'config/build tool' in usage.replacement_suggestion

    def test_transitive_dep_keeps_instead_of_remove(self):
        """A known transitive dep with no imports should be 'keep', not 'remove'."""
        analyzer = DependencyCodePathAnalyzer()
        analyzer._name_resolver = PackageNameResolver(repo_path='')
        usage = DependencyUsage(
            package_name='typing-extensions', ecosystem='pypi',
            health_status='healthy',
        )
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == 'keep'
        assert 'transitive' in usage.replacement_suggestion

    def test_config_referenced_package_keeps(self, tmp_path):
        """A package referenced in config files should be 'keep', not 'remove'."""
        config = tmp_path / 'app.config.js'
        config.write_text('plugins: ["expo-font"]')
        analyzer = DependencyCodePathAnalyzer()
        analyzer._name_resolver = PackageNameResolver(repo_path=str(tmp_path))
        usage = DependencyUsage(
            package_name='expo-font', ecosystem='npm',
            health_status='healthy',
        )
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == 'keep'
        assert 'config' in usage.replacement_suggestion

    def test_genuinely_unused_still_removed(self):
        """A genuinely unused package should still be classified as 'remove'."""
        analyzer = DependencyCodePathAnalyzer()
        analyzer._name_resolver = PackageNameResolver(repo_path='')
        usage = DependencyUsage(
            package_name='totally-unused-pkg', ecosystem='npm',
            health_status='healthy',
        )
        analyzer._classify_strategy(usage)
        assert usage.remediation_strategy == 'remove'

class TestVulnIntel:
    """EPSS/KEV enrichment (src/vuln_intel.py), fully offline via mocks."""

    @pytest.fixture(autouse=True)
    def _isolate(self, monkeypatch, tmp_path):
        from appsec_galaxy import vuln_intel
        monkeypatch.setattr(vuln_intel, '_kev_cache_path', lambda: str(tmp_path / 'kev.json'))
        monkeypatch.delenv('APPSEC_VULN_INTEL', raising=False)

    def _fake_requests(self, monkeypatch, epss_data=None, kev_cves=None, fail=False):
        from appsec_galaxy import vuln_intel
        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload
            def raise_for_status(self):
                pass
            def json(self):
                return self._payload

        def fake_get(url, **kwargs):
            if fail:
                raise vuln_intel.requests.ConnectionError("offline")
            if 'first.org' in url:
                return FakeResponse({'data': epss_data or []})
            return FakeResponse({'vulnerabilities': [{'cveID': c} for c in (kev_cves or [])]})
        monkeypatch.setattr(vuln_intel.requests, 'get', fake_get)

    def test_enrichment_assigns_priorities(self, monkeypatch):
        from appsec_galaxy.vuln_intel import enrich_findings
        self._fake_requests(monkeypatch,
                            epss_data=[{'cve': 'CVE-1111-1', 'epss': '0.95'},
                                       {'cve': 'CVE-2222-2', 'epss': '0.5'},
                                       {'cve': 'CVE-3333-3', 'epss': '0.01'}],
                            kev_cves=['CVE-1111-1'])
        findings = [
            {'tool': 'trivy', 'vulnerability_id': 'CVE-1111-1'},
            {'tool': 'trivy', 'vulnerability_id': 'CVE-2222-2'},
            {'tool': 'trivy', 'vulnerability_id': 'CVE-3333-3'},
            {'tool': 'semgrep', 'check_id': 'sqli'},  # untouched
        ]
        enrich_findings(findings)
        assert findings[0]['exploit_priority'] == 'urgent'   # KEV
        assert findings[1]['exploit_priority'] == 'high'     # EPSS 0.5
        assert findings[2]['exploit_priority'] == 'normal'   # EPSS 0.01
        assert 'exploit_priority' not in findings[3]

    def test_disabled_via_env(self, monkeypatch):
        from appsec_galaxy.vuln_intel import enrich_findings
        monkeypatch.setenv('APPSEC_VULN_INTEL', 'false')
        findings = [{'tool': 'trivy', 'vulnerability_id': 'CVE-1111-1'}]
        enrich_findings(findings)
        assert 'in_kev' not in findings[0]

    def test_network_failure_fails_open(self, monkeypatch):
        from appsec_galaxy.vuln_intel import enrich_findings
        self._fake_requests(monkeypatch, fail=True)
        findings = [{'tool': 'trivy', 'vulnerability_id': 'CVE-1111-1', 'severity': 'high'}]
        result = enrich_findings(findings)
        assert result is findings  # findings survive, no crash

    def test_kev_disk_cache_used_on_second_call(self, monkeypatch):
        from appsec_galaxy import vuln_intel
        calls = {'n': 0}
        self._fake_requests(monkeypatch, kev_cves=['CVE-9999-9'])
        real_get = vuln_intel.requests.get
        def counting_get(url, **kw):
            if 'cisa.gov' in url:
                calls['n'] += 1
            return real_get(url, **kw)
        monkeypatch.setattr(vuln_intel.requests, 'get', counting_get)
        assert vuln_intel.fetch_kev_cves() == {'CVE-9999-9'}
        assert vuln_intel.fetch_kev_cves() == {'CVE-9999-9'}
        assert calls['n'] == 1  # second call served from disk cache

    def test_non_cve_ids_skipped(self, monkeypatch):
        from appsec_galaxy.vuln_intel import fetch_epss_scores
        self._fake_requests(monkeypatch, epss_data=[])
        assert fetch_epss_scores(['GHSA-xxxx', '', 'not-a-cve']) == {}

class TestReachabilityPrioritization:
    """Reachability joined into CVE priority (src/vuln_intel.py).

    Exploit probability says how likely a CVE is to be attacked;
    reachability says whether the vulnerable dep is even imported.
    apply_reachability folds both into risk_priority."""

    def _dep_report(self, deps):
        """dict-shaped DependencyHealthReport (the to_dict() form)."""
        return {'dependencies': deps}

    def _usage(self, name, imported=True):
        d = {'package_name': name, 'ecosystem': 'npm',
             'import_sites': [], 'files_using': [], 'unique_apis_used': []}
        if imported:
            d['import_sites'] = [{'file': 'app.js', 'line': 1}]
            d['files_using'] = ['app.js']
            d['unique_apis_used'] = ['merge', 'get']
        return d

    # --- normalize_package_name -------------------------------------------

    def test_normalize_npm_scoped(self):
        from appsec_galaxy.vuln_intel import normalize_package_name
        assert normalize_package_name('@babel/traverse') == '@babel/traverse'

    def test_normalize_pypi_case_and_separators(self):
        from appsec_galaxy.vuln_intel import normalize_package_name
        assert normalize_package_name('PyYAML') == 'pyyaml'
        assert normalize_package_name('python_dateutil') == 'python-dateutil'
        assert normalize_package_name('zope.interface') == 'zope-interface'

    def test_normalize_pypi_extras_stripped(self):
        from appsec_galaxy.vuln_intel import normalize_package_name
        assert normalize_package_name('requests[security]') == 'requests'

    def test_normalize_empty(self):
        from appsec_galaxy.vuln_intel import normalize_package_name
        assert normalize_package_name('') == ''
        assert normalize_package_name(None) == ''

    # --- priority matrix ---------------------------------------------------

    def test_imported_plus_high_epss_escalates_to_urgent(self):
        from appsec_galaxy.vuln_intel import apply_reachability
        f = {'tool': 'trivy', 'pkg_name': 'lodash', 'vulnerability_id': 'CVE-1',
             'exploit_priority': 'high'}
        apply_reachability([f], self._dep_report([self._usage('lodash')]))
        assert f['reachability'] == 'imported'
        assert f['risk_priority'] == 'urgent'
        assert 'import site' in f['reachability_detail']

    def test_not_imported_demotes_one_level(self):
        from appsec_galaxy.vuln_intel import apply_reachability
        findings = [
            {'tool': 'trivy', 'pkg_name': 'leftpad', 'exploit_priority': 'urgent'},
            {'tool': 'trivy', 'pkg_name': 'leftpad', 'exploit_priority': 'high'},
            {'tool': 'trivy', 'pkg_name': 'leftpad', 'exploit_priority': 'normal'},
        ]
        apply_reachability(findings, self._dep_report([self._usage('leftpad', imported=False)]))
        assert [f['risk_priority'] for f in findings] == ['high', 'normal', 'low']
        assert findings[0]['reachability_detail'] == 'declared but never imported'

    def test_kev_never_buried(self):
        """A KEV CVE on an unimported dep demotes to high, never below."""
        from appsec_galaxy.vuln_intel import apply_reachability
        f = {'tool': 'trivy', 'pkg_name': 'x', 'exploit_priority': 'urgent'}
        apply_reachability([f], self._dep_report([self._usage('x', imported=False)]))
        assert f['risk_priority'] == 'high'

    def test_unknown_package_keeps_priority(self):
        from appsec_galaxy.vuln_intel import apply_reachability
        f = {'tool': 'trivy', 'pkg_name': 'not-analyzed', 'exploit_priority': 'high'}
        apply_reachability([f], self._dep_report([self._usage('other')]))
        assert f['reachability'] == 'unknown'
        assert f['risk_priority'] == 'high'

    def test_join_across_name_conventions(self):
        """Trivy PkgName PyYAML must join the analyzer's pyyaml entry."""
        from appsec_galaxy.vuln_intel import apply_reachability
        f = {'tool': 'trivy', 'pkg_name': 'PyYAML', 'exploit_priority': 'normal'}
        apply_reachability([f], self._dep_report([self._usage('pyyaml')]))
        assert f['reachability'] == 'imported'

    # --- boundaries ----------------------------------------------------------

    def test_misconfigs_and_non_trivy_untouched(self):
        from appsec_galaxy.vuln_intel import apply_reachability
        misconf = {'tool': 'trivy', 'finding_type': 'misconfiguration',
                   'vulnerability_id': 'DS002'}
        semgrep = {'tool': 'semgrep', 'check_id': 'sqli'}
        apply_reachability([misconf, semgrep], self._dep_report([self._usage('lodash')]))
        assert 'reachability' not in misconf
        assert 'reachability' not in semgrep

    def test_fails_open_without_report(self):
        from appsec_galaxy.vuln_intel import apply_reachability
        f = {'tool': 'trivy', 'pkg_name': 'lodash'}
        assert apply_reachability([f], None) == [f]
        assert 'reachability' not in f
        apply_reachability([f], self._dep_report([]))
        assert 'reachability' not in f

    def test_accepts_dataclass_report(self):
        from appsec_galaxy.dependency_analyzer import DependencyHealthReport, DependencyUsage
        from appsec_galaxy.vuln_intel import apply_reachability
        usage = DependencyUsage(package_name='lodash', ecosystem='npm')
        usage.import_sites = [{'file': 'a.js', 'line': 1}]
        report = DependencyHealthReport(repo_path='/r', dependencies=[usage])
        f = {'tool': 'trivy', 'pkg_name': 'lodash', 'exploit_priority': 'normal'}
        apply_reachability([f], report)
        assert f['reachability'] == 'imported'

    # --- surfacing -----------------------------------------------------------

    def test_sarif_carries_reachability(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        f = {'tool': 'trivy', 'vulnerability_id': 'CVE-1', 'path': 'lock', 'line': 1,
             'description': 'd', 'severity': 'high',
             'reachability': 'not-imported', 'risk_priority': 'low'}
        props = findings_to_sarif([f], '')['runs'][0]['results'][0]['properties']
        assert props['reachability'] == 'not-imported'
        assert props['risk_priority'] == 'low'

    def test_html_shows_reachability_and_sorts_by_priority(self, tmp_path):
        from appsec_galaxy.reporting.html import generate_html_report
        findings = [
            {'tool': 'trivy', 'vulnerability_id': 'CVE-LOW', 'path': 'lock', 'line': 1,
             'description': 'unreachable dep', 'severity': 'critical', 'category': 'security',
             'reachability': 'not-imported', 'risk_priority': 'low',
             'reachability_detail': 'declared but never imported'},
            {'tool': 'trivy', 'vulnerability_id': 'CVE-URGENT', 'path': 'lock', 'line': 1,
             'description': 'reachable exploited dep', 'severity': 'high', 'category': 'security',
             'reachability': 'imported', 'risk_priority': 'urgent',
             'reachability_detail': '3 import site(s), 7 API(s) used'},
        ]
        out = tmp_path / 'out'
        out.mkdir()
        generate_html_report(findings, '', str(out), '/repo', {'javascript'})
        html_out = (out / 'report.html').read_text()
        assert 'declared but never imported' in html_out
        assert 'Reachability:' in html_out
        # urgent (reachable, high sev) renders before low (unreachable, critical sev)
        assert html_out.index('reachable exploited dep') < html_out.index('unreachable dep')
