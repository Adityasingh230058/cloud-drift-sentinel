# Contributing to Cloud Drift Sentinel

Thank you for your interest in contributing to **Cloud Drift Sentinel**!

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/cloud-drift-sentinel.git
   cd cloud-drift-sentinel
   ```

2. **Create a virtual environment and install in editable mode:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Run the test suite:**
   ```bash
   pytest --cov=sentinel --cov-report=term-missing tests/
   ```

## 📋 Pull Request Guidelines

- Ensure all new CIS rules or cloud scanners include automated unit tests under `tests/`.
- Maintain code formatting adhering to PEP 8 / `black`.
- Use descriptive commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification.
