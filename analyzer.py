
import ast
import re

SEVERITY_ORDER = {
    "High": 0,
    "Medium": 1,
    "Low": 2
}


def create_finding(severity, line, title, description, suggestion, evidence=""):
    return {
        "severity": severity,
        "line": line,
        "title": title,
        "description": description,
        "suggestion": suggestion,
        "evidence": evidence.strip()
    }


def analyze_code(source):
    findings = []
    syntax_error = None

    # Parse Python source code.
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        tree = None
        syntax_error = (
            f"{error.msg} at line {error.lineno or 1}"
        )

    lines = source.splitlines()

    # Rule 1: Potential hard-coded credentials.
    secret_pattern = re.compile(
        r"""(?i)\b(api[_-]?key|password|secret|token)\b"""
        r"""\s*=\s*["'][^"']{6,}["']"""
    )

    # Rule 2: Potentially dangerous dynamic execution.
    dangerous_functions = {
        "eval": (
            "High",
            "Use of eval()",
            "eval() dynamically evaluates Python expressions. "
            "Untrusted input may lead to code execution.",
            "Avoid eval(). Use safe parsing or explicit conversions."
        ),
        "exec": (
            "High",
            "Use of exec()",
            "exec() dynamically executes Python code and can be "
            "dangerous when the source is untrusted.",
            "Replace dynamic execution with explicit functions."
        )
    }

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip simple comments to reduce false positives.
        if stripped.startswith("#"):
            continue

        if secret_pattern.search(line):
            findings.append(create_finding(
                "High",
                line_number,
                "Possible hard-coded secret",
                "A variable that resembles a credential is assigned "
                "a string literal. It may be a placeholder, but "
                "real credentials should not be committed.",
                "Read secrets from environment variables or a "
                "secrets manager. Rotate any exposed real credentials.",
                line
            ))

        for function_name, details in dangerous_functions.items():
            if re.search(
                rf"\b{function_name}\s*\(",
                line
            ):
                severity, title, description, suggestion = details

                findings.append(create_finding(
                    severity,
                    line_number,
                    title,
                    description,
                    suggestion,
                    line
                ))

        # Rule 3: Broad exception handling.
        if re.search(r"\bexcept\s*:", line):
            findings.append(create_finding(
                "Medium",
                line_number,
                "Bare except clause",
                "A bare except catches almost every exception and "
                "may hide programming errors.",
                "Catch specific exception types and handle them "
                "deliberately.",
                line
            ))

        # Rule 4: Risky subprocess shell execution.
        if re.search(
            r"\bsubprocess\.(run|Popen|call|check_output)\s*\(",
            line
        ) and re.search(r"\bshell\s*=\s*True\b", line):
            findings.append(create_finding(
                "High",
                line_number,
                "Potential shell command injection",
                "This subprocess call enables shell execution. "
                "If untrusted data reaches the command, it may "
                "allow unintended command execution.",
                "Prefer a list of arguments and avoid shell=True "
                "where possible. Validate external input.",
                line
            ))

        # Rule 5: SQL query string construction.
        if re.search(
            r"""(?i)\bexecute\s*\(\s*["'].*(%s|\{\}|%\s*\(|\+\s*)""",
            line
        ):
            findings.append(create_finding(
                "High",
                line_number,
                "Possible SQL injection",
                "The SQL execution call may build a query using "
                "string formatting or concatenation.",
                "Use parameterized SQL queries supported by your "
                "database library.",
                line
            ))

    # AST-based checks.
    if tree is not None:
        for node in ast.walk(tree):

            # Rule 6: Mutable default arguments.
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                defaults = node.args.defaults + [
                    default
                    for default in node.args.kw_defaults
                    if default is not None
                ]

                for default in defaults:
                    if isinstance(
                        default,
                        (ast.List, ast.Dict, ast.Set)
                    ):
                        findings.append(create_finding(
                            "Medium",
                            node.lineno,
                            "Mutable default argument",
                            f"Function '{node.name}' uses a mutable "
                            "default value that may be shared between "
                            "calls.",
                            "Use None as the default and create a "
                            "new collection inside the function.",
                            f"Function: {node.name}"
                        ))
                        break

            # Rule 7: Dangerous deserialization.
            if isinstance(node, ast.Call):
                function_name = ""

                if isinstance(node.func, ast.Name):
                    function_name = node.func.id

                elif isinstance(node.func, ast.Attribute):
                    function_name = node.func.attr

                if function_name == "pickle_loads" or (
                    function_name == "loads"
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "pickle"
                ):
                    findings.append(create_finding(
                        "High",
                        getattr(node, "lineno", 1),
                        "Potential unsafe pickle deserialization",
                        "Loading untrusted pickle data can execute "
                        "arbitrary code.",
                        "Never load pickle data from untrusted sources. "
                        "Consider safer data formats such as JSON.",
                        "pickle.loads(...)"
                    ))

    # Remove duplicate findings.
    unique_findings = {}

    for finding in findings:
        key = (
            finding["severity"],
            finding["line"],
            finding["title"]
        )
        unique_findings[key] = finding

    findings = list(unique_findings.values())

    # Sort higher-severity findings first.
    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER[item["severity"]],
            item["line"],
            item["title"]
        )
    )

    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for finding in findings:
        counts[finding["severity"]] += 1

    return {
        "findings": findings,
        "syntax_error": syntax_error,
        "counts": counts
    }
