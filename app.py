
import streamlit as st
from analyzer import analyze_code

st.set_page_config(
    page_title="CodeSage AI | Code Reviewer",
    page_icon="🧠",
    layout="wide"
)

# ---------------- PAGE HEADER ----------------

st.title("🧠 CodeSage AI")
st.subheader("Intelligent Python Code Review Assistant")

st.markdown(
    """
    Review Python code for potential security risks, common bugs,
    and code-quality problems. Get explanations and suggested fixes.
    """
)

st.divider()

# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.header("About CodeSage AI")

    st.write(
        "CodeSage AI uses Python AST parsing and rule-based "
        "static analysis to identify selected code issues."
    )

    st.markdown("### Current checks")
    st.write("🔴 Potential security risks")
    st.write("🟠 Common programming mistakes")
    st.write("🔵 Code-quality concerns")

    st.info(
        "No API key is required. This prototype analyzes code "
        "locally and does not send it to an external AI service."
    )

    st.caption(
        "Static analysis is a helpful first check, not a guarantee "
        "that code is secure or bug-free."
    )

# ---------------- CODE INPUT ----------------

st.header("1. Submit Python Code")

uploaded_file = st.file_uploader(
    "Upload a Python file",
    type=["py"]
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
        st.error("Unable to read this file. Please upload UTF-8 text.")
else:
    code = st.text_area(
        "Or paste your Python code here",
        value=default_code,
        height=280,
        placeholder="Paste Python code to review..."
    )

review_clicked = st.button(
    "🔍 Review Code",
    type="primary",
    use_container_width=True
)

# ---------------- ANALYSIS ----------------

if review_clicked:
    if not code.strip():
        st.warning("Please paste code or upload a Python file.")
    else:
        result = analyze_code(code)

        st.divider()
        st.header("2. Review Results")

        if result["syntax_error"]:
            st.error(
                f"Python syntax error: {result['syntax_error']}"
            )

        findings = result["findings"]
        counts = result["counts"]

        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Issues", len(findings))
        col2.metric("🔴 High", counts["High"])
        col3.metric("🟠 Medium", counts["Medium"])
        col4.metric("🔵 Low", counts["Low"])

        st.divider()

        if not findings:
            st.success(
                "No issues were detected by the current analysis rules."
            )
            st.write(
                "This does not prove that the code is free from bugs "
                "or security vulnerabilities."
            )
        else:
            # Filter controls
            selected_severity = st.multiselect(
                "Filter by severity",
                options=["High", "Medium", "Low"],
                default=["High", "Medium", "Low"]
            )

            visible_findings = [
                finding
                for finding in findings
                if finding["severity"] in selected_severity
            ]

            st.write(
                f"Showing {len(visible_findings)} of "
                f"{len(findings)} findings."
            )

            # Show individual findings
            for index, finding in enumerate(visible_findings, start=1):
                heading = (
                    f'{finding["severity"]} | '
                    f'Line {finding["line"]} | '
                    f'{finding["title"]}'
                )

                with st.expander(heading, expanded=(index == 1)):
                    st.markdown("**Explanation**")
                    st.write(finding["description"])

                    st.markdown("**Suggested improvement**")
                    st.write(finding["suggestion"])

                    if finding.get("evidence"):
                        st.markdown("**Evidence**")
                        st.code(
                            finding["evidence"],
                            language="python"
                        )

        # ---------------- DOWNLOAD REPORT ----------------

        report_lines = [
            "# CodeSage AI — Code Review Report",
            "",
            f"Total findings: {len(findings)}",
            f"High severity: {counts['High']}",
            f"Medium severity: {counts['Medium']}",
            f"Low severity: {counts['Low']}",
            ""
        ]

        if result["syntax_error"]:
            report_lines.extend([
                "## Syntax Error",
                result["syntax_error"],
                ""
            ])

        for finding in findings:
            report_lines.extend([
                f'## [{finding["severity"]}] '
                f'Line {finding["line"]}: {finding["title"]}',
                "",
                finding["description"],
                "",
                "**Suggested improvement:**",
                finding["suggestion"],
                ""
            ])

            if finding.get("evidence"):
                report_lines.extend([
                    "**Evidence:**",
                    f'`{finding["evidence"]}`',
                    ""
                ])

        st.divider()
        st.header("3. Export Report")

        st.download_button(
            label="⬇️ Download Review Report",
            data="\n".join(report_lines),
            file_name="codesage-review-report.md",
            mime="text/markdown",
            use_container_width=True
        )

# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "CodeSage AI | Python Static Analysis Prototype | "
    "Rule-based findings may include false positives or miss issues."
)
