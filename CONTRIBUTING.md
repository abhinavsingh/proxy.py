# Contributing to proxy.py

This document describes how contributors can participate and iterate quickly while maintaining the `proxy.py` project standards and guidelines.

## Basic Guidelines

* Your pull request should NOT introduce any external dependency.
* It is OK to use external dependencies within plugins.

## Environment Setup

Contributors must start `proxy.py` from source to verify and develop new features / fixes.  See [Run proxy.py from command line using repo source](#from-command-line-using-repo-source) for usage instructions.

[![WARNING](https://img.shields.io/static/v1?label=MacOS&message=warning&color=red)](https://github.com/abhinavsingh/proxy.py/issues/642#issuecomment-960819271) On `macOS` you must install `Python` using `pyenv`, as `Python` installed via `homebrew` tends to be problematic.  See linked thread for more details.

### Setup Git Hooks

You SHOULD NOT avoid these steps.  Git hooks will help catch test or linting errors locally without pushing to upstream.  This will save you a lot of time and allow you to contribute and iterate faster.

Pre-commit hook ensures tests are passing.

1. `cd /path/to/proxy.py`
2. `ln -s $(PWD)/git-pre-commit .git/hooks/pre-commit`

Pre-push hook ensures lint and tests are passing.

1. `cd /path/to/proxy.py`
2. `ln -s $(PWD)/git-pre-push .git/hooks/pre-push`

### Sending a Pull Request

All pull requests are tested using GitHub actions.

See [GitHub workflow](https://github.com/abhinavsingh/proxy.py/tree/develop/.github/workflows) for list of workflows.

## Communication

During the process of PR review, sometimes, you may get asked to update certain project configs.  Example, a change in code introduced via your PR will result in a redundant lint guard.  So we must make corresponding changes to ensure project health.

It's highly recommended that you participate in maintaining a high code-quality standard.  For any reason, if you are unable to address the requested changes, please communicate the same to the reviewer.

Thank you!!!
