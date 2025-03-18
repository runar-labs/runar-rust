# Rust Monorepo\n\nThis is the main monorepo for Runar Labs Rust projects.

## Repository Structure

This monorepo contains the following submodules:

- `node_webui`: Node.js web UI components
- `rust-apps`: Rust applications
- `rust-common`: Common Rust libraries and utilities
- `rust-docs`: Documentation for Rust projects
- `rust-e2e-test`: End-to-end tests for Rust applications
- `rust-examples`: Example Rust code and projects
- `rust-macros`: Rust macros
- `rust-node`: Rust-Node.js integration

## Working with Git Submodules

### Cloning the Repository

To clone this repository along with all submodules, use:

```bash
git clone --recurse-submodules git@github.com:runar-labs/rust-mono.git
```

### If You've Already Cloned the Repository

If you've already cloned the repository without the submodules, you can initialize and update them with:

```bash
git submodule update --init --recursive
```

### Updating Submodules

To update all submodules to their latest commits:

```bash
git submodule update --recursive --remote
```

### Working with Individual Submodules

To work with an individual submodule:

1. Navigate to the submodule directory:
   ```bash
   cd <submodule-name>
   ```

2. The submodule is a complete git repository. You can make changes, commit, and push directly:
   ```bash
   git checkout main  # or any branch you want to work on
   # make changes
   git add .
   git commit -m "Your commit message"
   git push
   ```

3. After pushing changes in a submodule, go back to the root directory and update the reference:
   ```bash
   cd ..
   git add <submodule-name>
   git commit -m "Update submodule reference"
   git push
   ```

### Adding a New Submodule

To add a new submodule:

```bash
git submodule add git@github.com:runar-labs/new-repo-name.git
git commit -m "Add new submodule"
git push
```
