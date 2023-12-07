#!/bin/bash

nancy --version
nancy-fixer --version

echo "Running nancy-fixer"
nancy-fixer fix
