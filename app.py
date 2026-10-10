import json
import streamlit as st
from analyzer import analyze_code
from bandit_analyzer import run_bandit


st.set_page_config(
    page_title="CodeSage AI | Code Reviewer",
    page_icon="🧠",
    layout="wide"
)


def deduplicate_findings(findings):
    """Merge overlapping detections from CodeSage Custom and Bandit."""
    unique = {}

    def issue_key(item):
        title = str(item.get("title", "")).lower()
        test_id = str(item.get("test_id", "")).upper()
        line = item.get("line", "?")
        evidence = " ".join(
            str(item.get("evidence", "")).split()
        ).lower()

        if test_id == "B307" or "eval()" in title or "eval(" in title:
            issue = "eval"
        elif test_id == "B602" or "shell command injection" in title:
            issue = "shell-injection"
        elif "hard-coded secret" in title or "hardcoded secret" in title:
            issue = "hardcoded-secret"
        else:
            issue = evidence or title

        return line, issue

    severity_rank = {
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    for finding in findings:
        key = issue_key(finding)

        if key not in unique:
            merged = dict(finding)
            merged["_engines"] = [
                finding.get("engine", "Unknown")
            ]
            unique[key] = merged
        else:
            existing = unique[key]
            engine = finding.get("engine", "Unknown")

            if engine not in existing["_engines"]:
                existing["_engines"].append(engine)

            for field, value in finding.items():
                if field == "engine":
                    continue

                if field not in existing or not existing[field]:
                    existing[field] = value

            current_severity = existing.get("severity", "Low")
            new_severity = finding.get("severity", "Low")

            if severity_rank.get(new_severity, 0) > severity_rank.get(
                current_severity, 0
            ):
                existing["severity"] = new_severity

    result = []

    for finding in unique.values():
        finding["engine"] = " + ".join(
            finding.pop("_engines")
        )
        result.append(finding)

    return result


def build_markdown_report(findings, counts):
    """Create a Markdown report from consolidated findings."""
    report = [
        "# CodeSage AI — Code Review Report",
        "",
        f"Total unique findings: {len(findings)}",
        f"High: {counts['High']}",
        f"Medium: {counts['Medium']}",
        f"Low: {counts['Low']}",
        "",
        "## Findings",
        ""
    ]

    for item in findings:
        report.extend([
            f'### [{item.get("severity", "Unknown")}] '
            f'Line {item.get("line", "?")}: '
            f'{item.get("title", "Finding")}',
            "",
            f'Analysis engine(s): {item.get("engine", "Unknown")}',
            "",
            "**Explanation:**",
            "",
            item.get("description", "No description available."),
            "",
            "**Suggested improvement:**",
            "",
            item.get("suggestion", "Review this finding."),
            ""
        ])

        if item.get("test_id"):
            report.extend([
                f'Bandit rule: {item["test_id"]}',
                ""
            ])

        if item.get("evidence"):
            report.extend([
                "**Evidence:**",
                "",
                "```python",
                item["evidence"],
                "```",
                ""
            ])

    report.extend([
        "---",
        "",
        "Static analysis may produce false positives or miss issues. "
        "Review findings before making changes."
    ])

    return "\n".join(report)


def build_json_report(findings, counts):
    """Create a structured JSON report."""
    report_data = {
        "project": "CodeSage AI",
        "report_type": "Python Static Code Analysis",
        "summary": {
            "total_findings": len(findings),
            "high": counts["High"],
            "medium": counts["Medium"],
            "low": counts["Low"]
        },
        "findings": [
            {
                "severity": item.get("severity", "Unknown"),
                "line": item.get("line"),
                "title": item.get("title", "Finding"),
                "description": item.get(
                    "description",
                    "No description available."
                ),
                "suggestion": item.get(
                    "suggestion",
                    "Review this finding."
                ),
                "engine": item.get("engine", "Unknown"),
                "test_id": item.get("test_id"),
                "confidence": item.get("confidence"),
                "evidence": item.get("evidence", "")
            }
            for item in findings
        ],
        "disclaimer": (
            "Static analysis may produce false positives or miss issues. "
            "Review findings before making changes."
        )
    }

    return json.dumps(report_data, indent=2, ensure_ascii=False)


st.title("🧠 CodeSage AI")
st.subheader("Intelligent Python Code Review Assistant")

st.markdown(
    "Review Python code using custom static-analysis rules "
    "and Bandit security analysis."
)


with st.sidebar:
    st.header("About CodeSage AI")
    st.write("Two analysis engines work together:")
    st.write("- Custom AST and pattern-based checks")
    st.write("- Bandit Python security checks")
    st.info(
        "The app analyzes source code without executing it. "
        "Static analysis cannot guarantee that code is secure."
    )


st.divider()
st.header("1. Submit Python Code")

uploaded_file = st.file_uploader(
    "Upload a Python file",
    type=["py"],
    help="Upload a Python source file for static analysis."
)

default_code = '''import subprocess

API_KEY = "example-secret-value"

def run_command(user_input, options=[]):
    result = eval(user_input)
    subprocess.run("echo " + user_input, shell=True)
    return result
'''

if uploaded_file is not None:
    try:
        code = uploaded_file.getvalue().decode("utf-8")
        st.success(f"Loaded file: {uploaded_file.name}")
    except UnicodeDecodeError:
        code = ""
        st.error("Please upload a UTF-8 encoded Python file.")
else:
    code = st.text_area(
        "Or paste Python code here",
        value=default_code,
        height=260
    )


run_custom = st.checkbox(
    "Run custom analysis",
    value=True
)

run_bandit_checks = st.checkbox(
    "Run Bandit security analysis",
    value=True
)


if st.button(
    "🔍 Review Code",
    type="primary",
    use_container_width=True
):
    if not code.strip():
        st.warning("Please paste or upload Python code.")

    elif not run_custom and not run_bandit_checks:
        st.warning("Select at least one analysis engine.")

    else:
        findings = []

        if run_custom:
            custom_result = analyze_code(code)

            if custom_result.get("syntax_error"):
                st.error(
                    "Python syntax error: "
                    + str(custom_result["syntax_error"])
                )

            for item in custom_result.get("findings", []):
                findings.append({
                    **item,
                    "engine": "CodeSage Custom"
                })

        if run_bandit_checks:
            with st.spinner("Running Bandit security analysis..."):
                bandit_result = run_bandit(code)

            if bandit_result.get("error"):
                st.error(
                    "Bandit analysis failed: "
                    + str(bandit_result["error"])
                )
            else:
                for item in bandit_result.get("findings", []):
                    findings.append({
                        **item,
                        "engine": "Bandit"
                    })

        findings = deduplicate_findings(findings)

        counts = {
            severity: sum(
                item.get("severity") == severity
                for item in findings
            )
            for severity in ["High", "Medium", "Low"]
        }

        st.divider()
        st.header("2. Review Results")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Total Findings", len(findings))
        c2.metric("🔴 High", counts["High"])
        c3.metric("🟠 Medium", counts["Medium"])
        c4.metric("🔵 Low", counts["Low"])

        if not findings:
            st.success(
                "No findings detected by the selected checks."
            )

        else:
            severity_filter = st.multiselect(
                "Filter by severity",
                ["High", "Medium", "Low"],
                default=["High", "Medium", "Low"]
            )

            visible = [
                item for item in findings
                if item.get("severity") in severity_filter
            ]

            st.write(
                f"Showing {len(visible)} of {len(findings)} findings."
            )

            for index, item in enumerate(visible, start=1):
                title = (
                    f'{item.get("severity", "Unknown")} | '
                    f'Line {item.get("line", "?")} | '
                    f'{item.get("title", "Finding")} | '
                    f'{item.get("engine", "Unknown")}'
                )

                with st.expander(title, expanded=(index == 1)):
                    st.write("**Analysis engine(s)**")
                    st.write(item.get("engine", "Unknown"))

                    if item.get("test_id"):
                        st.write("**Bandit rule**")
                        st.code(item["test_id"])

                    if item.get("confidence"):
                        st.write("**Confidence**")
                        st.write(item["confidence"])

                    st.write("**Explanation**")
                    st.write(
                        item.get(
                            "description",
                            "No description available."
                        )
                    )

                    st.write("**Suggested improvement**")
                    st.write(
                        item.get(
                            "suggestion",
                            "Review this finding."
                        )
                    )

                    if item.get("evidence"):
                        st.write("**Evidence**")
                        st.code(item["evidence"], language="python")

        # Build both reports from the same consolidated findings.
        markdown_report = build_markdown_report(findings, counts)
        json_report = build_json_report(findings, counts)

        st.divider()
        st.header("3. Export Report")

        col_md, col_json = st.columns(2)

        with col_md:
            st.download_button(
                "⬇️ Download Markdown Report",
                data=markdown_report,
                file_name="codesage-review-report.md",
                mime="text/markdown",
                use_container_width=True
            )

        with col_json:
            st.download_button(
                "⬇️ Download JSON Report",
                data=json_report,
                file_name="codesage-review-report.json",
                mime="application/json",
                use_container_width=True
            )


st.divider()

st.caption(
    "CodeSage AI | Custom Static Analysis + Bandit | "
    "Python security review prototype"
)
