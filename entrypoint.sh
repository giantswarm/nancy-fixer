#!/bin/bash

nancy --version
nancy-fixer --version

echo "Current directory: $(pwd)"
echo "Directory tree:"
ls -lah
echo "Running nancy-fixer"
nancy-fixer fix
