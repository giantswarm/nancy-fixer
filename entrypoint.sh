#!/bin/bash

set -xe

nancy --version
nancy-fixer --version

echo "Debugging nancy"

pwd
ls

echo "Finish debugging"

echo "Running nancy-fixer"
nancy-fixer fix
