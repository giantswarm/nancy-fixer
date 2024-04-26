#!/bin/bash

set -x

nancy --version
nancy-fixer --version

echo "Running nancy-fixer"
pwd
ls

nancy-fixer fix --log-level "debug"
