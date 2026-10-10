# CodeSage AI — Intelligent Python Code Review Assistant

CodeSage AI is a Python static analysis tool that reviews source code for selected security risks, common programming mistakes, and code-quality issues.

## Features

- **Security checks:** Detects potentially hard-coded secrets, `eval()`, `exec()`, unsafe shell execution, and potential SQL injection patterns.
- **Code-quality checks:** Identifies mutable default arguments and bare `except` clauses.
- **Syntax validation:** Reports Python syntax errors.
- **Severity classification:** Organizes findings into High, Medium, and Low categories.
- **Interactive dashboard:** Review findings through a Streamlit web interface.
- **Suggested improvements:** Provides explanations and recommendations for detected issues.
- **Report export:** Download code review results as a Markdown report.
- **Automated tests:** Uses Python's `unittest` framework to test important analysis rules.

## Tech Stack

- Python
- Streamlit
- Abstract Syntax Tree (AST)
- Regular expressions
- unittest

## Installation

1. Clone this repository:

   ```bash
   git clone YOUR_GITHUB_REPOSITORY_URL
   cd CodeSage-AI
   ```

2. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Run the application:

   ```bash
   python -m streamlit run app.py
   ```

4. Open the local URL displayed in the terminal.

## Run Automated Tests

```bash
python -m unittest -v test_analyzer.py
```

## How It Works

1. Submit Python source code by uploading a `.py` file or pasting code.
2. The analyzer checks the source using AST parsing and rule-based patterns.
3. Findings are assigned severity levels and include explanations and suggested improvements.
4. Review the findings in the dashboard and export a Markdown report.

## Current Limitations

CodeSage AI is an educational static analysis prototype. Its current rules are not a complete security audit and may produce false positives or miss vulnerabilities. It does not currently use a trained AI model or an external LLM API.

**Never upload real passwords, API keys, tokens, or confidential source code to an untrusted environment.**

## Future Improvements

- Add more security and code-quality rules.
- Improve detection accuracy with additional automated tests.
- Integrate established security tools such as Bandit.
- Add code-quality metrics and continuous integration using GitHub Actions.

## Author

Developed as a Python project to explore static analysis, secure coding practices, and developer tooling.