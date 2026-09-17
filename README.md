# encryption-demo

A small Python demo that teaches the basics of ECDSA, ECDHE, and HMAC-SHA256 with verbose, step-by-step logs.

## Important note

ECDSA is a **digital signature** algorithm, not an encryption algorithm. ECDHE is a **key exchange** mechanism. HMAC-SHA256 provides **message authentication and integrity**, not encryption. This project demonstrates each concept in separate demos.

## Project contents

- `src/encryption_demo/ecdsa.py` - ECDSA signing demo implementation
- `src/encryption_demo/ecdhe.py` - ECDHE key exchange demo implementation
- `src/encryption_demo/hmac_sha256.py` - HMAC-SHA256 authentication demo implementation
- `src/encryption_demo/demo.py` - CLI entrypoint that selects which demo to run
- `src/encryption_demo/__main__.py` - package entrypoint for module execution
- `tests/test_demo.py` - basic test coverage
- `.devcontainer/devcontainer.json` - dev container setup
- `.github/workflows/run-demo.yml` - GitHub Actions workflow that runs the demo and stores the log file

## Run locally

```bash
python -m pip install --upgrade pip
python -m pip install -e .
python -m encryption_demo
```

Run with a custom message:

```bash
python -m encryption_demo --message "Learning ECDSA"
```

Run the ECDHE key exchange demo:

```bash
python -m encryption_demo --demo ecdhe
```

Run the HMAC-SHA256 demo:

```bash
python -m encryption_demo --demo hmac --message "Learning HMAC" --key "shared secret"
```

## Run tests

```bash
python -m unittest discover -s tests
```

## Use the dev container

Open the repository in a dev-container-aware editor such as VS Code and reopen it in the container. The container installs the project automatically with:

```bash
pip install -e .
```

## GitHub Actions logs

The workflow at `.github/workflows/run-demo.yml` runs all three demos on every push and on manual dispatch.

To inspect logs for learning:

1. Open the **Actions** tab in GitHub.
2. Select the **Run Crypto Demos** workflow run.
3. Open the **Run ECDSA demo and capture logs**, **Run ECDHE demo and capture logs**, or **Run HMAC-SHA256 demo and capture logs** step to read the live console output.
4. Download the **ecdsa-demo-log**, **ecdhe-demo-log**, or **hmac-demo-log** artifact if you want the full saved log file.