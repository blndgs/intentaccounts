#!/bin/bash

# Initialize all submodules first
git submodule update --init

# Fix the ExcessivelySafeCall submodule in kernel
cd lib/kernel
git submodule deinit -f -- lib/ExcessivelySafeCall
rm -rf .git/modules/lib/ExcessivelySafeCall
git rm -f lib/ExcessivelySafeCall
git submodule add https://github.com/nomad-xyz/ExcessivelySafeCall lib/ExcessivelySafeCall
git submodule update --init --recursive
cd ../..