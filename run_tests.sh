#!/usr/bin/env sh

pyenv deactivate
pyenv activate pyas4

set -o pipefail
black --check as4 tests && mypy ./as4 && flake8 as4 tests && pytest
