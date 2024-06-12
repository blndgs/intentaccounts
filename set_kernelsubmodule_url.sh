#!/bin/bash

# Navigate to the kernel submodule directory
cd lib/kernel

# Remove the existing submodule reference if it exists
git submodule deinit -f -- lib/ExcessivelySafeCall
rm -rf .git/modules/lib/ExcessivelySafeCall
git rm -f lib/ExcessivelySafeCall

# Manually add the missing submodule with the correct URL
git submodule add https://github.com/nomad-xyz/ExcessivelySafeCall lib/ExcessivelySafeCall

# Initialize and update the submodules
git submodule update --init --recursive

# Go back to the root directory
cd ../..