#!/bin/bash

for dir in rust-node-api-test node_webui rust-apps rust-common rust-docs rust-e2e-test rust-examples rust-macros rust-macros-tests rust-node; do
  echo "Initializing Git in $dir"
  cd "$dir"
  git init
  echo "*.rs linguist-language=Rust" > .gitattributes
  echo "target/" > .gitignore
  echo "**/*.rs.bk" >> .gitignore
  echo "Cargo.lock" >> .gitignore
  git add .
  git commit -m "Initial commit for $dir submodule"
  cd ..
done

# Commit changes in the root repository
echo "Committing changes in the root repository"
git add .
git commit -m "Set up submodules and finalize EventHandlerService implementation"

echo "All repositories initialized and changes committed!" 