# encryption-demo

A small Python demo that teaches the basics of ECDSA by generating a key pair, signing a message, verifying the signature, and logging each step.

## Important note

ECDSA is a **digital signature** algorithm, not an encryption algorithm. This project demonstrates signing and verification because that is the correct use of ECDSA.

## Project contents

- `/home/runner/work/encryption-demo/encryption-demo/src/encryption_demo/demo.py` - ECDSA demo implementation
- `/home/runner/work/encryption-demo/encryption-demo/src/encryption_demo/__main__.py` - package entrypoint for module execution
- `/home/runner/work/encryption-demo/encryption-demo/tests/test_demo.py` - basic test coverage
- `/home/runner/work/encryption-demo/encryption-demo/.devcontainer/devcontainer.json` - dev container setup
- `/home/runner/work/encryption-demo/encryption-demo/.github/workflows/run-demo.yml` - GitHub Actions workflow that runs the demo and stores the log file

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

The workflow at `/home/runner/work/encryption-demo/encryption-demo/.github/workflows/run-demo.yml` runs the demo on every push and on manual dispatch.

To inspect logs for learning:

1. Open the **Actions** tab in GitHub.
2. Select the **Run ECDSA Demo** workflow run.
3. Open the **Run demo and capture logs** step to read the live console output.
4. Download the **ecdsa-demo-log** artifact if you want the full saved log file.