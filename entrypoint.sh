#!/bin/bash

set -x

nancy --version
nancy-fixer --version

echo "Running nancy-fixer"
echo $(pwd)

nancy-fixer fix
