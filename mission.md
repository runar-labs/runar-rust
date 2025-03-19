# Runar Project Restructuring and Migration

## Background

We have recently moved our code to a new repository structure. Now we need to rename components, update references, remove duplicate code, and ensure everything compiles and runs as expected.

Several duplicate packages exist (rust-common, kagi_utils, utils, kagi_node, test_service_info) that need to be consolidated. The rust-common crate should be the central location for all common utilities.

The core components of our system are:
- rust-node: The system core
- rust-macros: Contains the macro functionality that enables simple service definition

Currently, some macros exist in the core package that may need to be moved to the rust-macros crate. We need to analyze all macros to ensure they're in the appropriate locations.

The rust-apps submodule will contain components and applications built using Runar tools. This submodule will typically remain disabled to keep the monorepo manageable, but can be enabled when working on applications.

The rust-docs submodule will contain:
- Specifications (to be built into docs)
- Public documentation in Markdown format
- Website builder
- Built documentation website (HTML/CSS/JS)

We need to reorganize this submodule to host the built docs website as a GitHub Pages site.

We have also rebranded from "Kagi" to "Runar". We are now the Runar team, and our product is runar-node. To distinguish between implementations, we'll use the prefixes rust-, go-, and ts- (e.g., rust-runar-node, go-runar-node, ts-runar-node). All references to "Kagi" in code and documentation must be updated to "Runar".

# Runar Project Migration Plan

## 1. Code Consolidation and Deduplication

- [x] Analyze duplicate code between rust-common, kagi_utils, utils, kagi_node, test_service_info
- [x] Create a consolidation plan with mapping of which files go where
- [x] Move all common utilities and shared code to rust-common crate
- [x] Update all import paths across the codebase to point to consolidated code in rust-common
- [x] Ensure proper dependency structure in Cargo.toml files after consolidation
- [ ] Verify no critical functionality is lost during consolidation
- [ ] Update tests to reflect new import paths
- [ ] Verify the build works with consolidated code but before removing old packages
- [ ] Remove redundant packages after verification (kagi_utils, utils, etc.)

## 2. Renaming from Kagi to Runar

- [x] Create a comprehensive grep search to identify all "kagi" references throughout the codebase
- [x] Update all file and directory names from "kagi_*" to "runar_*"
- [x] Update package names in Cargo.toml files
- [x] Update module names and references in source code
- [ ] Update documentation references from "kagi" to "runar"
- [ ] Update README files and other project documentation
- [ ] Ensure all references to the project in comments are updated
- [ ] Verify proper references to implementations (rust-runar-node, go-runar-node, ts-runar-node)

## 3. Macro Analysis and Reorganization

- [x] Identify all macros across the codebase
- [x] Create inventory of macros in rust-node core package
- [x] Determine which macros should move to rust-macros
- [x] Migrate appropriate macros to rust-macros package
- [x] Update all references to moved macros
- [ ] Ensure backward compatibility or provide clear migration path
- [ ] Add comprehensive documentation for all macros and their usage
- [ ] Write tests for any moved macros

## 4. Rust-docs Reorganization

- [ ] Plan structure for GitHub Pages compatible documentation
- [ ] Create a clear separation between source docs and built docs
- [ ] Set up a build process for generating static website from markdown
- [ ] Organize specs, public docs, and website builder
- [ ] Create a GitHub Actions workflow for automatic docs deployment
- [ ] Test the GitHub Pages deployment
- [ ] Verify all documentation is up-to-date with the latest code changes
- [ ] Ensure correct implementation-specific references (rust-, go-, ts- prefixes)

## 5. Integration and Testing

- [ ] Verify that all crates build successfully after changes
- [ ] Run the full test suite across all submodules
- [ ] Ensure all examples work correctly
- [ ] Performance testing to verify no regressions
- [ ] Create integration tests that verify cross-module functionality
- [ ] Test on different platforms if applicable
- [ ] Document any breaking changes and required migrations for users

## 6. Post-Migration Tasks

- [ ] Update CI/CD pipelines to reflect new structure
- [ ] Create comprehensive project-wide documentation
- [ ] Review and update versioning strategy
- [ ] Create release notes detailing the migration
- [ ] Plan for future maintenance and development workflows
- [ ] Review security implications of the restructuring



