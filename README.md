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


Prompt Guidelines:
GPT 4.1 Prompting Guide Notes
Follow instructions literally. GPT-4.1 is trained to follow directions more precisely than previous models. Be explicit about what you want.

Place instructions strategically. For long context, put critical instructions at both the beginning AND end of your prompt for best results.

Use specific delimiters. Markdown headings, XML tags, and backticks help the model understand structure. JSON performs poorly for document collections.

Induce planning with prompting. Ask the model to “think step by step” when solving complex problems to significantly improve accuracy.

Design agentic workflows with clear reminders:
“Keep going until the problem is completely resolved”

“Use tools when uncertain instead of guessing”

“Plan extensively before each action”

Leverage the 1M token context window wisely. Performance stays strong up to the limit, but degrades when retrieving many items or reasoning across the entire context.

Balance internal vs. external knowledge. For factual queries, instruct the model to “only use provided context” or “combine with basic knowledge” based on your needs.

Format your prompts with clear sections:
Role and Objective

Instructions (with subcategories)

Reasoning Steps

Output Format

Examples

Final Instructions

Guide information retrieval. When working with documents, ask the model to first analyze which ones are relevant before attempting to answer.

Avoid rare prompt patterns. The model may struggle with extremely repetitive outputs or parallel tool calls. Test these cases carefully.

Be direct with corrections. If model behavior is unexpected, a single clear sentence is usually enough to steer it in the right direction.

Use specific frameworks for coding. For generating code changes, use the V4A diff format with context lines for maximum accuracy.

Remember it’s not a reasoning model. GPT-4.1 doesn’t automatically provide an internal chain of thought, but you can explicitly request it to show its work.


