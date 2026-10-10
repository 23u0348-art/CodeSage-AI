# CodeSage AI — Intelligent Python Code Review Assistant

CodeSage AI is a Python static analysis and security review tool that identifies potential vulnerabilities, common programming mistakes, and code-quality issues. It combines custom AST-based analysis with **Bandit**, a Python security analysis tool, and presents findings through an interactive Streamlit dashboard.

## Features

- **Security vulnerability detection:** Identifies potentially hard-coded secrets, dangerous use of `eval()`, unsafe shell execution, and selected SQL injection patterns.
- **Code-quality analysis:** Detects mutable default arguments and bare `except` clauses.
- **Syntax validation:** Reports Python syntax errors.
- **Bandit integration:** Uses an established Python security analyzer to identify additional security issues.
- **Severity classification:** Groups findings into High, Medium, and Low categories.
- **Interactive dashboard:** Submit Python code by uploading a file or pasting source code into the Streamlit interface.
- **Deduplicated findings:** Consolidates overlapping results from different analysis engines.
- **Report export:** Download code review results in Markdown and JSON formats.
- **Automated tests:** Includes unit tests for custom analysis rules and Bandit integration.

## Tech Stack

- Python
- Streamlit
- Abstract Syntax Tree (AST)
- Regular expressions
- Bandit
- Python `unittest`
- JSON and Markdown reporting

## Project Structure

```text
CodeSage-AI/
├── app.py
├── analyzer.py
├── bandit_analyzer.py
├── test_analyzer.py
├── test_bandit.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/23u0348-art/CodeSage-AI.git
cd CodeSage-AI
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Run the application

```bash
python -m streamlit run app.py
```

Open the local URL shown in your terminal to access the dashboard.

## How to Use

1. Open the CodeSage AI dashboard.
2. Upload a Python file or paste Python source code into the editor.
3. Select the analysis engines you want to use.
4. Run the analysis.
5. Review the findings, severity levels, explanations, and suggested fixes.
6. Download the results as a Markdown or JSON report.

## Running Tests

Run the custom analyzer tests:

```bash
python -m unittest -v test_analyzer.py
```

Run the Bandit integration tests:

```bash
python -m unittest -v test_bandit.py
```

Run both test suites:

```bash
python -m unittest -v test_analyzer.py test_bandit.py
```

## How It Works

1. The application accepts Python source code from the user.
2. The custom analyzer uses AST parsing and rule-based checks to inspect the code.
3. Bandit performs additional security analysis.
4. Results from the enabled analysis engines are consolidated to reduce duplicate findings.
5. The dashboard displays findings with severity, line numbers, descriptions, and suggested improvements.
6. Users can export the results as Markdown or JSON for further review.

## Current Limitations

CodeSage AI is an educational static analysis prototype, not a replacement for a professional security audit. Findings may include false positives, and some vulnerabilities may not be detected. Results depend on the rules and analysis engines enabled.

The project does not currently use a trained AI model or an external large language model API. Its analysis is based on custom static analysis rules and Bandit.

**Security note:** Do not upload real credentials, API keys, passwords, tokens, or confidential source code to an untrusted environment.

## Future Improvements

- Add more security rules and code-quality checks.
- Improve detection accuracy and test coverage.
- Add code complexity metrics and maintainability analysis.
- Introduce GitHub Actions for automated testing.
- Explore optional AI-assisted explanations and remediation suggestions.

## Author

Developed as a Python project to explore static analysis, secure coding practices, and developer tooling.