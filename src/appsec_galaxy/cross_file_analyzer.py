#!/usr/bin/env python3
"""
Cross-File Analyzer for AppSec Galaxy - Multi-File Security Analysis

This cross-file analyzer provides enhanced security analysis capabilities:
- Data flow tracing from user inputs to sensitive operations
- Attack path identification across multiple files
- Framework-aware vulnerability correlation
- Business impact assessment based on code architecture

Functions available to AI-assisted analysis:
- analyze_repository_structure(repo_path) -> Complete codebase overview
- trace_data_flow(repo_path, start_file, target_operation) -> Data flow paths
- find_attack_chains(repo_path, vulnerability_type) -> Cross-file attack vectors
- assess_business_impact(repo_path, finding) -> Risk analysis with context
"""

import ast
import json
import re
from pathlib import Path
from typing import Any
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class DataFlowNode:
    """Represents a node in the data flow graph"""
    file_path: str
    function_name: str
    line_number: int
    node_type: str  # 'input', 'transform', 'output', 'sink'
    risk_level: str  # 'high', 'medium', 'low'

@dataclass
class AttackChain:
    """Represents a potential attack chain across files"""
    vulnerability_type: str
    entry_point: str
    attack_path: list[str]
    sink: str
    severity: str
    business_impact: str
    description: str
    remediation: str

class CrossFileAnalyzer:
    """Real cross-file security analysis engine"""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.file_analysis_cache: dict[str, dict[str, Any]] = {}
        self.import_graph: dict[str, list[str]] = {}
        self.data_flow_graph: dict[str, list[str]] = {}
        self.entry_points: list[str] = []
        self.sensitive_sinks: list[str] = []
        self.external_imports: dict[str, list[dict[str, Any]]] = {}  # {module_name: [{file, line, imported_names}]}

    def analyze_repository_structure(self) -> dict[str, Any]:
        """
        Complete repository analysis with real cross-file understanding.

        Returns comprehensive analysis including:
        - Language and framework detection
        - Import/dependency relationships
        - Entry points (routes, endpoints)
        - Sensitive operations (DB queries, file ops)
        - Data flow patterns
        """
        logger.info(f"🔍 Starting comprehensive analysis of {self.repo_path}")

        # 1. Discover all source files
        source_files = self._discover_source_files()
        logger.info(f"Found {len(source_files)} source files to analyze")

        # 2. Analyze each file individually
        for file_path in source_files:
            self.file_analysis_cache[str(file_path)] = self._analyze_single_file(file_path)

        # 3. Build import/dependency graph
        self._build_import_graph()

        # 4. Identify entry points and sinks
        self._identify_entry_points_and_sinks()

        # 5. Build data flow graph
        self._build_data_flow_graph()

        structure = {
            "repo_path": str(self.repo_path),
            "total_files": len(source_files),
            "languages": self._get_detected_languages(),
            "frameworks": self._get_detected_frameworks(),
            "entry_points": [str(ep) for ep in self.entry_points],
            "sensitive_sinks": [str(sink) for sink in self.sensitive_sinks],
            "import_relationships": len(self.import_graph),
            "data_flow_edges": len(self.data_flow_graph),
            "analysis_summary": self._generate_analysis_summary()
        }

        logger.info(f"✅ Repository analysis complete: {structure['analysis_summary']}")
        return structure

    def trace_data_flow(self, start_file: str, target_operation: str | None = None) -> dict[str, Any]:
        """
        Trace data flow from a starting file to sensitive operations.

        Args:
            start_file: File to start tracing from (relative to repo)
            target_operation: Specific operation to trace to (optional)

        Returns:
            Dictionary containing all possible data flow paths
        """
        start_path = self.repo_path / start_file
        if not start_path.exists():
            return {"error": f"Start file not found: {start_file}"}

        logger.info(f"🔄 Tracing data flow from {start_file}")

        # Find all paths from start_file to sensitive operations
        flow_paths = []
        visited = set()

        def dfs_trace(current_file: str, current_path: list[str], depth: int = 0):
            if depth > 10 or current_file in visited:  # Prevent infinite loops
                return

            visited.add(current_file)
            current_path = current_path + [current_file]

            # Check if current file has sensitive operations
            file_analysis = self.file_analysis_cache.get(current_file, {})
            sensitive_ops = file_analysis.get('sensitive_operations', [])

            for op in sensitive_ops:
                if not target_operation or target_operation.lower() in op.get('operation', '').lower():
                    flow_paths.append({
                        "path": current_path,
                        "sink": current_file,
                        "operation": op,
                        "risk_level": self._assess_path_risk(current_path, op),
                        "description": self._describe_attack_path(current_path, op)
                    })

            # Continue tracing through imports
            for imported_file in self.import_graph.get(current_file, []):
                dfs_trace(imported_file, current_path, depth + 1)

            visited.remove(current_file)

        dfs_trace(str(start_path.relative_to(self.repo_path)), [])

        result = {
            "start_file": start_file,
            "target_operation": target_operation,
            "paths_found": len(flow_paths),
            "data_flow_paths": flow_paths,
            "summary": f"Found {len(flow_paths)} potential data flow paths from {start_file}"
        }

        logger.info(f"✅ Data flow tracing complete: {result['summary']}")
        return result

    def find_attack_chains(self, vulnerability_type: str | None = None) -> list[AttackChain]:
        """
        Find potential attack chains across multiple files.

        Args:
            vulnerability_type: Type of vulnerability to focus on (sql_injection, xss, etc.)

        Returns:
            List of AttackChain objects representing cross-file vulnerabilities
        """
        logger.info(f"⚔️ Searching for attack chains (type: {vulnerability_type or 'all'})")

        attack_chains = []

        # For each entry point, trace to each sensitive sink
        for entry_point in self.entry_points:
            for sink in self.sensitive_sinks:
                chains = self._find_attack_chains_between(entry_point, sink, vulnerability_type)
                attack_chains.extend(chains)

        # Sort by severity and business impact
        attack_chains.sort(key=lambda x: (
            0 if x.severity == 'critical' else 1 if x.severity == 'high' else 2,
            0 if 'high' in x.business_impact.lower() else 1
        ))

        logger.info(f"⚔️ Found {len(attack_chains)} potential attack chains")
        return attack_chains

    def assess_business_impact(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Assess business impact of a vulnerability with codebase context.

        Args:
            finding: Vulnerability finding from scanner

        Returns:
            Detailed business impact assessment
        """
        file_path = finding.get('path', '')
        finding.get('severity', 'unknown')
        vuln_type = finding.get('check_id', '').lower()

        impact: dict[str, Any] = {
            "financial_risk": "Low",
            "reputation_risk": "Low",
            "operational_risk": "Low",
            "compliance_risk": "Low",
            "context_factors": [],
            "business_justification": ""
        }

        # Analyze file location context
        if any(critical in file_path.lower() for critical in ['auth', 'login', 'admin', 'payment', 'user']):
            impact["context_factors"].append("Located in security-critical component")
            impact["financial_risk"] = "High"
            impact["reputation_risk"] = "High"

        # Check if file is an entry point (exposed to users)
        if file_path in [str(ep) for ep in self.entry_points]:
            impact["context_factors"].append("File is a user-facing entry point")
            impact["operational_risk"] = "Medium"

        # Vulnerability-specific impact
        if 'sql' in vuln_type or 'injection' in vuln_type:
            impact["financial_risk"] = "High"
            impact["compliance_risk"] = "High"
            impact["business_justification"] = "SQL injection can lead to data breaches and regulatory fines"

        elif 'secret' in vuln_type or 'credential' in vuln_type:
            impact["financial_risk"] = "High"
            impact["reputation_risk"] = "High"
            impact["business_justification"] = "Exposed credentials enable unauthorized access and data theft"

        elif 'xss' in vuln_type:
            impact["reputation_risk"] = "Medium"
            impact["business_justification"] = "XSS attacks can compromise user accounts and trust"

        # Framework-specific risks
        frameworks = self._get_detected_frameworks()
        if 'express' in frameworks and 'middleware' not in file_path:
            impact["context_factors"].append("Express.js route without apparent security middleware")

        return impact

    def _discover_source_files(self) -> list[Path]:
        """Discover all source files in the repository"""
        source_extensions = {
            '.py', '.js', '.mjs', '.ts', '.jsx', '.tsx',
            '.java', '.kt', '.go', '.rs', '.php', '.rb', '.cs'
        }
        source_files = []

        for file_path in self.repo_path.rglob('*'):
            if (file_path.is_file() and
                file_path.suffix in source_extensions and
                not any(exclude in str(file_path) for exclude in ['node_modules', '.git', '__pycache__', 'venv'])):
                source_files.append(file_path)

        return source_files

    def _analyze_single_file(self, file_path: Path) -> dict[str, Any]:
        """Analyze a single file for security-relevant patterns"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            analysis: dict[str, Any] = {
                "imports": [],
                "exports": [],
                "functions": [],
                "user_input_handlers": [],
                "sensitive_operations": [],
                "data_transformations": [],
                "framework_patterns": []
            }

            # Language-specific analysis
            if file_path.suffix == '.py':
                analysis.update(self._analyze_python_file(content))
            elif file_path.suffix in ['.js', '.mjs', '.ts', '.jsx', '.tsx']:
                analysis.update(self._analyze_javascript_file(content))
            elif file_path.suffix == '.java':
                analysis.update(self._analyze_java_file(content))
            elif file_path.suffix == '.go':
                analysis.update(self._analyze_go_file(content))
            elif file_path.suffix == '.php':
                analysis.update(self._analyze_php_file(content))
            elif file_path.suffix == '.rs':
                analysis.update(self._analyze_rust_file(content))
            elif file_path.suffix == '.cs':
                analysis.update(self._analyze_csharp_file(content))
            elif file_path.suffix in ['.rb']:
                analysis.update(self._analyze_ruby_file(content))
            elif file_path.suffix in ['.kt']:
                analysis.update(self._analyze_kotlin_file(content))

            return analysis

        except Exception as e:
            logger.debug(f"Failed to analyze {file_path}: {e}")
            return {}

    def _analyze_python_file(self, content: str) -> dict[str, Any]:
        """Deep analysis of Python files using AST"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                # Import analysis
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        analysis["imports"].append({"module": alias.name, "type": "import"})
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        analysis["imports"].append({"module": node.module, "function": alias.name, "type": "from_import"})

                # Function analysis
                elif isinstance(node, ast.FunctionDef):
                    func_info = {"name": node.name, "line": node.lineno, "args": [arg.arg for arg in node.args.args]}
                    analysis["functions"].append(func_info)

                    # Check for Flask/Django route handlers
                    for decorator in node.decorator_list:
                        if self._is_route_decorator(decorator):
                            analysis["user_input_handlers"].append({
                                "function": node.name, "line": node.lineno, "type": "route_handler"
                            })

                # Sensitive operation detection
                elif isinstance(node, ast.Call):
                    if self._is_sensitive_call_python(node):
                        analysis["sensitive_operations"].append({
                            "operation": self._get_call_name(node),
                            "line": node.lineno,
                            "type": self._classify_operation(node)
                        })

        except SyntaxError:
            pass  # Skip files with syntax errors

        return analysis

    def _analyze_javascript_file(self, content: str) -> dict[str, Any]:
        """Analysis of JavaScript/TypeScript files using regex patterns"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Enhanced import analysis
            import_patterns = [
                r'(?:import|require)\s*\([\'"]([^\'"]+)[\'"]',  # require('module')
                r'import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]',    # import x from 'module'
                r'const\s+\w+\s*=\s*require\([\'"]([^\'"]+)[\'"]'  # const x = require('module')
            ]
            for pattern in import_patterns:
                import_match = re.search(pattern, line)
                if import_match:
                    analysis["imports"].append({"module": import_match.group(1), "line": i})
                    break

            # Enhanced Express route detection
            route_patterns = [
                r'app\.(?:get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]*)[\'"]',  # app.get('/route')
                r'router\.(?:get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]*)[\'"]',  # router.get('/route')
                r'\.(?:get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]*)[\'"]'  # generic .get('/route')
            ]
            for pattern in route_patterns:
                route_match = re.search(pattern, line)
                if route_match:
                    analysis["user_input_handlers"].append({
                        "route": route_match.group(1), "line": i, "type": "express_route"
                    })
                    break

            # Enhanced database operations detection
            db_patterns = [
                r'\.(?:query|execute|find|save|create|update|delete)\s*\(',  # mongoose/sequelize
                r'db\.(?:query|execute|run|get|all)\s*\(',  # sqlite/generic db
                r'connection\.(?:query|execute)\s*\(',  # mysql connection
                r'client\.(?:query|execute)\s*\(',  # postgres client
                r'collection\.(?:find|insert|update|delete)\s*\('  # mongodb
            ]
            for pattern in db_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "database_operation"
                    })
                    break

            # Enhanced file operations detection
            file_patterns = [
                r'fs\.(?:readFile|writeFile|unlink|createReadStream|createWriteStream)',
                r'require\s*\(\s*[\'"]fs[\'"]',
                r'readFileSync|writeFileSync',
                r'path\.(?:join|resolve|normalize)'
            ]
            for pattern in file_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "file_operation"
                    })
                    break

            # Add user input detection
            input_patterns = [
                r'req\.(?:body|params|query|headers)',  # Express request objects
                r'request\.(?:body|params|query|headers)',  # Alternative request naming
                r'process\.argv',  # Command line arguments
                r'process\.env'  # Environment variables (could be user-controlled)
            ]
            for pattern in input_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({
                        "input_source": pattern, "line": i, "type": "user_input"
                    })
                    break

        return analysis

    def _analyze_java_file(self, content: str) -> dict[str, Any]:
        """Analysis of Java files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Import analysis
            if line.strip().startswith('import '):
                match = re.search(r'import\s+([^;]+);', line)
                if match:
                    analysis["imports"].append({"module": match.group(1), "line": i})

            # Spring Boot annotations
            if re.search(r'@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)', line):
                analysis["user_input_handlers"].append({"line": i, "type": "spring_endpoint"})

            # Database operations
            if re.search(r'\.(?:createQuery|createNativeQuery|find|save|delete)\s*\(', line):
                analysis["sensitive_operations"].append({
                    "operation": line.strip(), "line": i, "type": "database_operation"
                })

        return analysis

    def _analyze_go_file(self, content: str) -> dict[str, Any]:
        """Analysis of Go files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Import analysis
            match = re.search(r'import\s+[\'"]([^\'"]+)[\'"]', line)
            if match:
                analysis["imports"].append({"module": match.group(1), "line": i})

            # HTTP handlers
            if re.search(r'func\s+\w*[Hh]andler|\w+\.HandleFunc', line):
                analysis["user_input_handlers"].append({"line": i, "type": "http_handler"})

            # Database operations
            if re.search(r'\.(?:Query|Exec|Prepare)\s*\(', line):
                analysis["sensitive_operations"].append({
                    "operation": line.strip(), "line": i, "type": "database_operation"
                })

        return analysis

    def _analyze_php_file(self, content: str) -> dict[str, Any]:
        """Analysis of PHP files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # User input detection
            if re.search(r'\$_(?:GET|POST|REQUEST|COOKIE|SESSION)', line):
                analysis["user_input_handlers"].append({"line": i, "type": "user_input"})

            # Database operations
            if re.search(r'(?:mysql_query|mysqli_query|->query|->prepare|->execute)', line):
                analysis["sensitive_operations"].append({
                    "operation": line.strip(), "line": i, "type": "database_operation"
                })

        return analysis

    def _analyze_rust_file(self, content: str) -> dict[str, Any]:
        """Enhanced analysis of Rust files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Import analysis
            import_patterns = [
                r'use\s+([^;]+);',  # use statements
                r'extern\s+crate\s+(\w+);',  # external crates
            ]
            for pattern in import_patterns:
                match = re.search(pattern, line)
                if match:
                    analysis["imports"].append({"module": match.group(1), "line": i})
                    break

            # HTTP handlers (Actix, Rocket, Warp)
            handler_patterns = [
                r'#\[(?:get|post|put|delete|patch)\(',  # Actix/Rocket macros
                r'\.route\(',  # Route definitions
                r'warp::',  # Warp framework
                r'axum::',  # Axum framework
            ]
            for pattern in handler_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({"line": i, "type": "http_handler"})
                    break

            # User input detection
            input_patterns = [
                r'std::env::args',  # Command line args
                r'std::env::var',  # Environment variables
                r'Query\s*<',  # Query parameters
                r'Json\s*<',  # JSON body
                r'Form\s*<',  # Form data
            ]
            for pattern in input_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({
                        "input_source": pattern, "line": i, "type": "user_input"
                    })
                    break

            # Database operations
            db_patterns = [
                r'sqlx::',  # SQLx database
                r'diesel::',  # Diesel ORM
                r'rusqlite::',  # SQLite
                r'redis::',  # Redis client
                r'mongodb::',  # MongoDB driver
            ]
            for pattern in db_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "database_operation"
                    })
                    break

            # File operations
            file_patterns = [
                r'std::fs::',  # File system operations
                r'tokio::fs::',  # Async file operations
                r'File::(?:open|create)',  # File operations
            ]
            for pattern in file_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "file_operation"
                    })
                    break

        return analysis

    def _analyze_csharp_file(self, content: str) -> dict[str, Any]:
        """Enhanced analysis of C# files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Import analysis
            import_patterns = [
                r'using\s+([^;]+);',  # using statements
                r'using\s+static\s+([^;]+);',  # static using
            ]
            for pattern in import_patterns:
                match = re.search(pattern, line)
                if match:
                    analysis["imports"].append({"module": match.group(1), "line": i})
                    break

            # ASP.NET Core controllers
            controller_patterns = [
                r'\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route)\]',  # HTTP attributes
                r'public\s+class\s+\w+Controller',  # Controller classes
                r'ControllerBase',  # Controller inheritance
            ]
            for pattern in controller_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({"line": i, "type": "aspnet_controller"})
                    break

            # User input detection
            input_patterns = [
                r'Request\.',  # HTTP Request
                r'Console\.ReadLine',  # Console input
                r'Environment\.GetCommandLineArgs',  # Command line
                r'Environment\.GetEnvironmentVariable',  # Environment vars
                r'\[FromBody\]|\[FromQuery\]|\[FromRoute\]',  # Parameter binding
            ]
            for pattern in input_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({
                        "input_source": pattern, "line": i, "type": "user_input"
                    })
                    break

            # Database operations
            db_patterns = [
                r'SqlConnection|SqlCommand',  # ADO.NET
                r'EntityFramework|DbContext',  # Entity Framework
                r'IDbConnection|IDbCommand',  # Dapper
                r'\.Query\s*<|\.Execute\s*<',  # ORM queries
                r'Redis\.|StackExchange\.Redis',  # Redis
            ]
            for pattern in db_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "database_operation"
                    })
                    break

            # File operations
            file_patterns = [
                r'File\.',  # System.IO.File
                r'Directory\.',  # System.IO.Directory
                r'FileStream|StreamReader|StreamWriter',  # Streams
                r'Path\.',  # System.IO.Path
            ]
            for pattern in file_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "file_operation"
                    })
                    break

        return analysis

    def _analyze_ruby_file(self, content: str) -> dict[str, Any]:
        """Enhanced analysis of Ruby files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Import analysis
            import_patterns = [
                r'require\s+["\']([^"\']+)["\']',  # require statements
                r'require_relative\s+["\']([^"\']+)["\']',  # relative requires
                r'load\s+["\']([^"\']+)["\']',  # load statements
            ]
            for pattern in import_patterns:
                match = re.search(pattern, line)
                if match:
                    analysis["imports"].append({"module": match.group(1), "line": i})
                    break

            # Rails controllers
            controller_patterns = [
                r'class\s+\w+Controller',  # Controller classes
                r'ApplicationController',  # Rails controller inheritance
                r'def\s+(?:index|show|create|update|destroy)',  # RESTful actions
            ]
            for pattern in controller_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({"line": i, "type": "rails_controller"})
                    break

            # User input detection
            input_patterns = [
                r'params\[',  # Rails parameters
                r'request\.',  # Request object
                r'ARGV',  # Command line args
                r'ENV\[',  # Environment variables
                r'gets',  # User input
            ]
            for pattern in input_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({
                        "input_source": pattern, "line": i, "type": "user_input"
                    })
                    break

            # Database operations
            db_patterns = [
                r'ActiveRecord::|\.find\(|\.where\(|\.create\(|\.update\(',  # ActiveRecord
                r'Sequel\.',  # Sequel ORM
                r'Redis\.',  # Redis client
                r'Mongo\.',  # MongoDB client
                r'execute\s*\(',  # Raw SQL execution
            ]
            for pattern in db_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "database_operation"
                    })
                    break

            # File operations
            file_patterns = [
                r'File\.',  # File operations
                r'Dir\.',  # Directory operations
                r'IO\.',  # IO operations
                r'open\s*\(',  # File opening
            ]
            for pattern in file_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "file_operation"
                    })
                    break

        return analysis

    def _analyze_kotlin_file(self, content: str) -> dict[str, Any]:
        """Enhanced analysis of Kotlin files"""
        analysis: dict[str, Any] = {"imports": [], "functions": [], "user_input_handlers": [], "sensitive_operations": []}

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Import analysis
            if line.strip().startswith('import '):
                match = re.search(r'import\s+([^\s]+)', line)
                if match:
                    analysis["imports"].append({"module": match.group(1), "line": i})

            # Spring Boot / Ktor annotations
            controller_patterns = [
                r'@(?:RestController|Controller|RequestMapping|GetMapping|PostMapping)',  # Spring
                r'@(?:Get|Post|Put|Delete|Patch)',  # Ktor
                r'routing\s*\{',  # Ktor routing
            ]
            for pattern in controller_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({"line": i, "type": "kotlin_endpoint"})
                    break

            # User input detection
            input_patterns = [
                r'call\.parameters|call\.receive',  # Ktor
                r'@RequestParam|@PathVariable|@RequestBody',  # Spring
                r'System\.getProperty',  # System properties
                r'readLine\(\)',  # Console input
            ]
            for pattern in input_patterns:
                if re.search(pattern, line):
                    analysis["user_input_handlers"].append({
                        "input_source": pattern, "line": i, "type": "user_input"
                    })
                    break

            # Database operations (similar to Java but with Kotlin syntax)
            db_patterns = [
                r'\.(?:find|save|delete|persist|merge)\s*\(',  # JPA
                r'jdbcTemplate\.',  # Spring JDBC
                r'Exposed\.',  # Exposed ORM
                r'transaction\s*\{',  # Database transactions
            ]
            for pattern in db_patterns:
                if re.search(pattern, line):
                    analysis["sensitive_operations"].append({
                        "operation": line.strip()[:100], "line": i, "type": "database_operation"
                    })
                    break

        return analysis

    def _build_import_graph(self):
        """Build graph of file dependencies, tracking external (unresolved) imports."""
        for file_path, analysis in self.file_analysis_cache.items():
            imports = analysis.get('imports', [])
            self.import_graph[file_path] = []

            for imp in imports:
                # Try to resolve import to actual file
                resolved_path = self._resolve_import(imp, file_path)
                if resolved_path:
                    self.import_graph[file_path].append(resolved_path)
                else:
                    # Unresolved import: likely an external package
                    module = imp.get('module', '')
                    if module and not module.startswith('.'):
                        pkg_name = self._extract_package_name_from_import(module)
                        if pkg_name not in self.external_imports:
                            self.external_imports[pkg_name] = []
                        self.external_imports[pkg_name].append({
                            'file': file_path,
                            'line': imp.get('line', 0),
                            'module': module,
                            'imported_names': imp.get('names', []),
                        })

    @staticmethod
    def _extract_package_name_from_import(module: str) -> str:
        """
        Normalize an import path to a top-level package name.

        Examples:
            flask.views      → flask
            @babel/core      → @babel/core
            lodash/merge     → lodash
            org.example.Foo  → org.example
        """
        if not module:
            return ''
        # npm scoped: @scope/package/...
        if module.startswith('@'):
            parts = module.split('/')
            return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else module
        # Java-style dotted: org.example.ClassName
        if '.' in module and '/' not in module:
            return module.split('.')[0]
        # Path-style: lodash/merge
        return module.split('/')[0]

    def _resolve_import(self, import_info: dict[str, str], source_file: str) -> str | None:
        """Resolve an import to an actual file path"""
        module = import_info.get('module', '')

        # Handle relative imports (./file, ../file)
        if module.startswith('.'):
            source_dir = Path(source_file).parent
            relative_path = source_dir / module.lstrip('./')

            # Try different extensions
            for ext in ['.py', '.js', '.ts', '.java', '.go', '.php']:
                if (self.repo_path / f"{relative_path}{ext}").exists():
                    return str((self.repo_path / f"{relative_path}{ext}").relative_to(self.repo_path))

        # Handle Java package imports (org.example.ClassName -> org/example/ClassName.java)
        if '.' in module and not module.startswith('.'):
            # Try treating as Java package
            java_path = module.replace('.', '/') + '.java'
            for source_file_path in self.file_analysis_cache.keys():
                if source_file_path.endswith(java_path):
                    return source_file_path

            # Try last component only (ClassName from org.example.ClassName)
            last_component = module.split('.')[-1]
            for source_file_path in self.file_analysis_cache.keys():
                if last_component in source_file_path and source_file_path.endswith('.java'):
                    return source_file_path

        # Handle absolute imports within project (for other languages)
        for source_file_path in self.file_analysis_cache.keys():
            if module in source_file_path:
                return source_file_path

        return None

    def _identify_entry_points_and_sinks(self):
        """Identify entry points (user input) and sinks (sensitive operations)"""
        for file_path, analysis in self.file_analysis_cache.items():
            # Entry points: files that handle user input
            if analysis.get('user_input_handlers'):
                self.entry_points.append(file_path)

            # Sinks: files with sensitive operations
            if analysis.get('sensitive_operations'):
                self.sensitive_sinks.append(file_path)

    def _build_data_flow_graph(self):
        """Build data flow graph showing how data moves between files"""
        # For each import relationship, create a data flow edge
        for source_file, imported_files in self.import_graph.items():
            for target_file in imported_files:
                if source_file not in self.data_flow_graph:
                    self.data_flow_graph[source_file] = []
                self.data_flow_graph[source_file].append(target_file)

    def _find_attack_chains_between(self, entry_point: str, sink: str, vuln_type: str | None) -> list[AttackChain]:
        """Find attack chains between specific entry point and sink"""
        chains = []
        paths = self._find_paths_between_files(entry_point, sink)

        for path in paths:
            chain = self._create_attack_chain(path, vuln_type)
            if chain:
                chains.append(chain)

        return chains

    def _find_paths_between_files(self, start_file: str, end_file: str) -> list[list[str]]:
        """Find all paths between two files in the data flow graph"""
        paths = []
        visited = set()

        def dfs_path(current: str, target: str, path: list[str]):
            if current == target:
                paths.append(path + [current])
                return

            if current in visited or len(path) > 8:  # Prevent infinite loops
                return

            visited.add(current)

            for neighbor in self.data_flow_graph.get(current, []):
                dfs_path(neighbor, target, path + [current])

            visited.remove(current)

        dfs_path(start_file, end_file, [])
        return paths

    def _create_attack_chain(self, path: list[str], vuln_type: str | None) -> AttackChain | None:
        """Create an AttackChain object from a path"""
        if len(path) < 2:
            return None

        entry_point = path[0]
        sink = path[-1]

        # Determine vulnerability type and severity
        entry_analysis = self.file_analysis_cache.get(entry_point, {})
        sink_analysis = self.file_analysis_cache.get(sink, {})

        # Check if this actually represents a vulnerability
        has_input = bool(entry_analysis.get('user_input_handlers'))
        has_sink = bool(sink_analysis.get('sensitive_operations'))

        if not (has_input and has_sink):
            return None

        # Determine vulnerability type if not specified
        if not vuln_type:
            sink_ops = sink_analysis.get('sensitive_operations', [])
            if any('database' in op.get('type', '') for op in sink_ops):
                vuln_type = 'sql_injection'
            elif any('file' in op.get('type', '') for op in sink_ops):
                vuln_type = 'path_traversal'
            else:
                vuln_type = 'data_flow'

        severity = 'high' if len(path) <= 3 else 'medium'  # Shorter paths = higher risk

        return AttackChain(
            vulnerability_type=vuln_type,
            entry_point=entry_point,
            attack_path=path,
            sink=sink,
            severity=severity,
            business_impact=self._assess_chain_business_impact(path, vuln_type),
            description=self._describe_attack_chain(path, vuln_type),
            remediation=self._suggest_chain_remediation(path, vuln_type)
        )

    def _assess_path_risk(self, path: list[str], operation: dict[str, Any]) -> str:
        """Assess risk level of a data flow path"""
        if len(path) <= 2:
            return "high"  # Direct path = high risk
        elif len(path) <= 4:
            return "medium"
        else:
            return "low"

    def _describe_attack_path(self, path: list[str], operation: dict[str, Any]) -> str:
        """Describe what the attack path represents"""
        if len(path) == 1:
            return f"Direct vulnerability in {path[0]}"
        else:
            return f"Data flows from {path[0]} through {' → '.join(path[1:-1])} to {path[-1]}"

    def _assess_chain_business_impact(self, path: list[str], vuln_type: str) -> str:
        """Assess business impact of an attack chain"""
        # Check if any files in the path are in critical locations
        critical_keywords = ['auth', 'login', 'admin', 'payment', 'user', 'api']

        for file_path in path:
            if any(keyword in file_path.lower() for keyword in critical_keywords):
                return "High - involves critical business logic"

        if vuln_type in ['sql_injection', 'command_injection']:
            return "High - potential for data breach"
        elif vuln_type in ['xss', 'path_traversal']:
            return "Medium - user data at risk"
        else:
            return "Low - limited exposure"

    def _describe_attack_chain(self, path: list[str], vuln_type: str) -> str:
        """Provide detailed description of the attack chain"""
        entry = Path(path[0]).name
        sink = Path(path[-1]).name

        descriptions = {
            'sql_injection': f"User input from {entry} flows to database query in {sink}, enabling SQL injection",
            'xss': f"User input from {entry} flows to output in {sink} without proper sanitization",
            'path_traversal': f"User input from {entry} flows to file operation in {sink}, enabling path traversal",
            'command_injection': f"User input from {entry} flows to system command in {sink}",
        }

        return descriptions.get(vuln_type, f"Data flows from {entry} to {sink} through {len(path)-2} intermediate files")

    def _suggest_chain_remediation(self, path: list[str], vuln_type: str) -> str:
        """Suggest remediation for the attack chain"""
        remediations = {
            'sql_injection': "Implement parameterized queries and input validation at entry point",
            'xss': "Add output encoding and Content Security Policy",
            'path_traversal': "Validate and sanitize file paths, use allowlists",
            'command_injection': "Avoid system commands with user input, use safe APIs",
        }

        return remediations.get(vuln_type, "Implement input validation and output sanitization")

    def _get_detected_languages(self) -> list[str]:
        """Get list of detected programming languages"""
        languages = set()
        for file_path in self.file_analysis_cache.keys():
            ext = Path(file_path).suffix
            lang_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.tsx': 'typescript',
                '.jsx': 'javascript',
                '.java': 'java',
                '.kt': 'kotlin',
                '.go': 'go',
                '.rs': 'rust',
                '.php': 'php',
                '.rb': 'ruby',
                '.cs': 'csharp',
                '.fs': 'fsharp',
                '.vb': 'vb.net',
                '.cpp': 'cpp',
                '.cc': 'cpp',
                '.c': 'c',
                '.h': 'c/cpp',
                '.hpp': 'cpp',
                '.swift': 'swift',
                '.scala': 'scala',
                '.clj': 'clojure',
                '.ex': 'elixir',
                '.exs': 'elixir'
            }
            if ext in lang_map:
                languages.add(lang_map[ext])
        return list(languages)

    def _get_detected_frameworks(self) -> list[str]:
        """Get list of detected frameworks across all languages"""
        frameworks = set()

        # Check for framework indicators in imports and patterns
        for analysis in self.file_analysis_cache.values():
            imports = analysis.get('imports', [])
            for imp in imports:
                module = imp.get('module', '').lower()

                # JavaScript/TypeScript frameworks
                if 'express' in module:
                    frameworks.add('express')
                elif 'react' in module:
                    frameworks.add('react')
                elif 'vue' in module:
                    frameworks.add('vue')
                elif 'angular' in module:
                    frameworks.add('angular')
                elif 'next' in module:
                    frameworks.add('nextjs')
                elif 'fastify' in module:
                    frameworks.add('fastify')

                # Python frameworks
                elif 'flask' in module:
                    frameworks.add('flask')
                elif 'django' in module:
                    frameworks.add('django')
                elif 'fastapi' in module:
                    frameworks.add('fastapi')
                elif 'tornado' in module:
                    frameworks.add('tornado')
                elif 'pyramid' in module:
                    frameworks.add('pyramid')

                # Java/Kotlin frameworks
                elif 'spring' in module:
                    frameworks.add('spring')
                elif 'springboot' in module:
                    frameworks.add('spring-boot')
                elif 'jersey' in module:
                    frameworks.add('jersey')
                elif 'dropwizard' in module:
                    frameworks.add('dropwizard')
                elif 'quarkus' in module:
                    frameworks.add('quarkus')
                elif 'ktor' in module:
                    frameworks.add('ktor')

                # Go frameworks
                elif 'gin' in module:
                    frameworks.add('gin')
                elif 'echo' in module:
                    frameworks.add('echo')
                elif 'fiber' in module:
                    frameworks.add('fiber')
                elif 'beego' in module:
                    frameworks.add('beego')
                elif 'iris' in module:
                    frameworks.add('iris')

                # Rust frameworks
                elif 'actix' in module:
                    frameworks.add('actix-web')
                elif 'rocket' in module:
                    frameworks.add('rocket')
                elif 'warp' in module:
                    frameworks.add('warp')
                elif 'axum' in module:
                    frameworks.add('axum')

                # C# frameworks
                elif 'aspnet' in module or 'microsoft.aspnetcore' in module:
                    frameworks.add('asp.net-core')
                elif 'mvc' in module:
                    frameworks.add('asp.net-mvc')
                elif 'webapi' in module:
                    frameworks.add('asp.net-webapi')

                # Ruby frameworks
                elif 'rails' in module or 'actionpack' in module:
                    frameworks.add('rails')
                elif 'sinatra' in module:
                    frameworks.add('sinatra')
                elif 'grape' in module:
                    frameworks.add('grape')

                # PHP frameworks
                elif 'laravel' in module:
                    frameworks.add('laravel')
                elif 'symfony' in module:
                    frameworks.add('symfony')
                elif 'codeigniter' in module:
                    frameworks.add('codeigniter')
                elif 'zend' in module:
                    frameworks.add('zend')

        return list(frameworks)

    def _generate_analysis_summary(self) -> str:
        """Generate a summary of the analysis"""
        entry_count = len(self.entry_points)
        sink_count = len(self.sensitive_sinks)
        import_count = sum(len(imports) for imports in self.import_graph.values())

        return f"{entry_count} entry points, {sink_count} sensitive sinks, {import_count} import relationships"

    # Helper methods for AST analysis
    def _is_route_decorator(self, decorator) -> bool:
        """Check if a decorator is a route decorator"""
        if isinstance(decorator, ast.Attribute):
            return decorator.attr in ['route', 'get', 'post', 'put', 'delete']
        elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
            return decorator.func.attr in ['route', 'get', 'post', 'put', 'delete']
        return False

    def _is_sensitive_call_python(self, node: ast.Call) -> bool:
        """Check if a function call is security-sensitive"""
        call_name = self._get_call_name(node)
        sensitive_patterns = [
            'execute', 'query', 'eval', 'exec', 'system', 'subprocess',
            'open', 'file', 'input', 'raw_input'
        ]
        return any(pattern in call_name.lower() for pattern in sensitive_patterns)

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        else:
            return "unknown"

    def _classify_operation(self, node: ast.Call) -> str:
        """Classify the type of sensitive operation"""
        call_name = self._get_call_name(node).lower()

        if any(db in call_name for db in ['execute', 'query', 'sql']):
            return 'database_operation'
        elif any(file_op in call_name for file_op in ['open', 'file', 'read', 'write']):
            return 'file_operation'
        elif any(cmd in call_name for cmd in ['system', 'subprocess', 'exec']):
            return 'command_execution'
        else:
            return 'unknown'


# Global analyzer instance for the cross-file analyzer
analyzer = None

def analyze_repository_structure(repo_path: str) -> dict[str, Any]:
    """
    Analysis function: Analyze complete repository structure

    Args:
        repo_path: Path to repository to analyze

    Returns:
        Complete structural analysis of the codebase
    """
    global analyzer
    analyzer = CrossFileAnalyzer(repo_path)

    try:
        result = analyzer.analyze_repository_structure()
        return {
            "status": "success",
            "analysis": result,
            "analyzer_version": "2.0",
            "capabilities": ["cross_file_analysis", "data_flow_tracing", "attack_chain_detection"]
        }
    except Exception as e:
        logger.error(f"Repository analysis failed: {e}")
        return {"status": "error", "error": str(e)}

def trace_data_flow(repo_path: str, start_file: str, target_operation: str | None = None) -> dict[str, Any]:
    """
    Analysis function: Trace data flow from entry point to sensitive operations

    Args:
        repo_path: Repository path
        start_file: File to start tracing from
        target_operation: Specific operation to trace to (optional)

    Returns:
        Data flow analysis results
    """
    global analyzer
    if not analyzer or str(analyzer.repo_path) != repo_path:
        analyzer = CrossFileAnalyzer(repo_path)
        analyzer.analyze_repository_structure()

    try:
        result = analyzer.trace_data_flow(start_file, target_operation)
        return {"status": "success", "analysis": result}
    except Exception as e:
        logger.error(f"Data flow tracing failed: {e}")
        return {"status": "error", "error": str(e)}

def find_attack_chains(repo_path: str, vulnerability_type: str | None = None) -> dict[str, Any]:
    """
    Analysis function: Find potential attack chains across files

    Args:
        repo_path: Repository path
        vulnerability_type: Type of vulnerability to focus on

    Returns:
        List of potential attack chains
    """
    global analyzer
    if not analyzer or str(analyzer.repo_path) != repo_path:
        analyzer = CrossFileAnalyzer(repo_path)
        analyzer.analyze_repository_structure()

    try:
        chains = analyzer.find_attack_chains(vulnerability_type)
        return {
            "status": "success",
            "attack_chains": [asdict(chain) for chain in chains],
            "total_chains": len(chains),
            "summary": f"Found {len(chains)} potential attack chains"
        }
    except Exception as e:
        logger.error(f"Attack chain analysis failed: {e}")
        return {"status": "error", "error": str(e)}

def assess_business_impact(repo_path: str, finding: dict[str, Any]) -> dict[str, Any]:
    """
    Analysis function: Assess business impact of a vulnerability

    Args:
        repo_path: Repository path
        finding: Vulnerability finding

    Returns:
        Business impact assessment
    """
    global analyzer
    if not analyzer or str(analyzer.repo_path) != repo_path:
        analyzer = CrossFileAnalyzer(repo_path)
        analyzer.analyze_repository_structure()

    try:
        impact = analyzer.assess_business_impact(finding)
        return {"status": "success", "impact": impact}
    except Exception as e:
        logger.error(f"Business impact assessment failed: {e}")
        return {"status": "error", "error": str(e)}

# Standalone execution for testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        repo_path = sys.argv[1]
        result = analyze_repository_structure(repo_path)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python cross_file_analyzer.py <repo_path>")
