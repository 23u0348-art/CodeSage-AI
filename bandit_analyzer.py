
import json
import os
import subprocess
import sys
import tempfile


def run_bandit(source_code):
    """Analyze Python source with Bandit without executing it."""
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            encoding="utf-8",
            delete=False
        ) as temp_file:
            temp_file.write(source_code)
            temp_path = temp_file.name

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                temp_path
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False
        )

        if not result.stdout.strip():
            return {
                "findings": [],
                "error": result.stderr.strip() or
                         "Bandit did not return analysis results."
            }

        data = json.loads(result.stdout)
        findings = []

        severity_map = {
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low"
        }

        for issue in data.get("results", []):
            findings.append({
                "severity": severity_map.get(
                    issue.get("issue_severity", "").upper(),
                    "Low"
                ),
                "line": issue.get("line_number", 1),
                "title": issue.get("test_name", "Security finding"),
                "description": issue.get("issue_text", ""),
                "suggestion": (
                    "Review this finding and follow the guidance "
                    "for the identified Bandit security test."
                ),
                "evidence": (issue.get("code") or "").strip(),
                "test_id": issue.get("test_id", ""),
                "confidence": issue.get("issue_confidence", "")
            })

        return {
            "findings": findings,
            "error": None
        }

    except subprocess.TimeoutExpired:
        return {
            "findings": [],
            "error": "Bandit analysis timed out. Try a smaller file."
        }
    except (OSError, json.JSONDecodeError) as error:
        return {
            "findings": [],
            "error": f"Bandit analysis failed: {error}"
        }
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
