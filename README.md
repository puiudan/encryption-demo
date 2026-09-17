# cryptography-demos

A small Python demo that teaches the basics of SHA-256, AES-GCM, and RSA-PSS with verbose, step-by-step logs.

## Important note

SHA-256 is a **hash** function. AES-GCM is an **authenticated encryption** mode. RSA-PSS is a **digital signature** scheme. This project demonstrates each concept in separate demos.

## Project contents

- `src/encryption_demo/sha256.py` - SHA-256 hashing demo implementation
- `src/encryption_demo/aes_gcm.py` - AES-GCM authenticated encryption demo implementation
- `src/encryption_demo/rsa_pss.py` - RSA-PSS signing demo implementation
- `src/encryption_demo/demo.py` - CLI entrypoint that selects which demo to run
- `src/encryption_demo/__main__.py` - package entrypoint for module execution
- `tests/test_demo.py` - basic test coverage
- `.devcontainer/devcontainer.json` - dev container setup
- `.github/workflows/run-demo.yml` - GitHub Actions workflow that runs the demo and stores log files

## Run locally

```bash
python -m pip install --upgrade pip
python -m pip install -e .
python -m encryption_demo
```

Run with a custom message:

```bash
python -m encryption_demo --message "Learning SHA-256"
```

Run the AES-GCM demo:

```bash
python -m encryption_demo --demo aes-gcm --message "Learning AES-GCM" --aad "demo aad"
```

Run the RSA-PSS demo:

```bash
python -m encryption_demo --demo rsa-pss --message "Learning RSA-PSS"
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
3. Open the **Run SHA-256 demo and capture logs**, **Run AES-GCM demo and capture logs**, or **Run RSA-PSS demo and capture logs** step to read the live console output.
4. Download the **sha256-demo-log**, **aes-gcm-demo-log**, or **rsa-pss-demo-log** artifact if you want the full saved log file.
