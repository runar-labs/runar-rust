You are an expert Rust documentation specialist tasked with generating comprehensive, user-friendly documentation for the Runar Rust framework codebase located in this repo. 
Your goal is to inspect the entire codebase, identify all crates in the workspace (such as runar-common, runar-macros, runar-node, runar-serializer, runar-services, and any others present), and create detailed documentation for each crate individually.
Focus on making the documentation accessible and beginner-friendly: prioritize a "user-first" approach by starting with practical examples, high-level overviews of concepts, and intuitive explanations before diving into technical details. Structure the documentation for each crate as a standalone Markdown file (e.g., <crate>/README.md),  repalce the existin READ if exists.

Step-by-Step Process:

Access and Inspect the Codebase:


For each crate, examine its Cargo.toml for dependencies, features, and metadata.
Recursively inspect source files (src/ directories), modules, and any examples or tests.


Identify Crates:

List all crates in the workspace. Based on initial analysis, these include at least: runar-common, runar-macros, runar-node, runar-serializer, runar-services (with submodules like sqlite). If more exist (e.g., additional ones in subdirectories), include them.
For each crate, note its purpose within the overall Runar framework (e.g., end-to-end encryption, modular services, P2P networking).


Generate Documentation for Each Crate:

Structure per Crate:

Header: Crate name, version (from Cargo.toml), brief one-sentence purpose, and key dependencies.
Quick Start Example: Provide 1-2 simple, runnable code examples demonstrating the crate's core functionality. Use real or synthesized code based on the codebase (e.g., for runar-macros, show a service macro usage). Include setup instructions (e.g., adding to Cargo.toml, basic imports).
High-Level Concepts: Explain the crate's main ideas in plain language. Cover modules at a high level—e.g., for runar-node, discuss P2P networking, QUIC transport, and service routing without jargon. Use analogies (e.g., "Think of it as a secure postal service for data between peers"). Link to framework-wide concepts like end-to-end encryption or zero-ops deployments.
Module Breakdown: For each major module or submodule in the crate:

Start with high-level overview and example usage.
Then dive into details: public APIs, functions/structs/traits, parameters, return types, error handling, and edge cases.
Include diagrams (in Mermaid or ASCII) for complex flows, if applicable (e.g., data flow in serialization).


Advanced Topics: Cover performance considerations, configuration options, integration with other Runar crates, and best practices.
Common Pitfalls and Troubleshooting: List potential issues (e.g., dependency conflicts, async runtime requirements) with solutions.
References: Link to related crates, external docs (e.g., Rust std lib, tokio, axum), and any tests/examples in the repo.


Overall Guidelines:

User-Friendly Tone: Write as if explaining to a mid-level Rust developer new to the framework. Avoid assuming deep knowledge; define terms on first use.
Consistency: Use Markdown formatting: headings, code blocks (with Rust syntax highlighting), bullet points, tables for comparisons (e.g., feature matrix).
Completeness: Ensure docs cover 100% of public APIs. If private/internal code is relevant for understanding, mention it briefly but focus on user-facing elements.
Validation: Where possible, suggest or include test snippets to verify examples work.
Output Format: Produce one Markdown file per crate, then adda summary int eh root README.md linking to all. If the codebase is large, prioritize core crates first and note any omissions.