#!/bin/bash

# Guessed Version 2.3.2.dev146+gad54132.d20211114
python -m setuptools_scm --version | \
    # 2.3.2.dev146+gad54132.d20211114
    awk '{print $3}' | \
    # 2.3.2.dev146-gad54132.d20211114
    sed 's/\+/-/' | \
    # 2.3.2.dev146-gad54132-d20211114
    sed -E 's/(.*)\./\1-/' | \
    # 2.3.2-dev146-gad54132-d20211114
    sed -E 's/(.*)\./\1-/'
