# Guidelines for Fixing Issues and Implementing Features

## General Workflow

When fixing issues or implementing new features, follow these steps:

- Before making any change, always check the design docs in the `docs/` folder
- Create a detailed plan and save it in a file under `spec/under_construction/`
- As you progress, keep the detailed plan up to date with:
  - Progress
  - Issues encountered
  - Solutions implemented
  - Design decisions made along the way
- At the end, use this plan as input for documentation updates
- Once all tests pass and documentation is updated, this file can be removed, signaling the work is complete

## Code Quality Guidelines

- For each file you touch, always clean up all warnings, unused code, etc.
- Keep the codebase clean - this includes formatting, naming, and organization

## Rust Best Practices

- Leverage Rust's type system to prevent errors at compile time
- Prefer ownership over borrowing when appropriate
- Handle errors appropriately (no unwraps in production code)
- Use `Option` and `Result` for representing potential absence or failure
- Follow the Rust naming conventions (snake_case for functions, CamelCase for types)
- Use enums for state machines and expressing variants
- Prefer composition over inheritance
- Use trait objects for runtime polymorphism only when needed
- Keep functions and methods focused - they should do one thing well
- Use meaningful error types that provide context
- Write documentation comments for public APIs
- Use lifetimes judiciously - keep them simple when possible
- Apply clippy lints to catch common mistakes and anti-patterns

## API Design Best Practices

- Design APIs from the consumer's perspective first
- Strive for simplicity and intuitiveness in public interfaces
- Return domain-specific values from functions rather than generic wrappers where possible
- For action handlers, return the actual data type (e.g., `Result<String>`) instead of wrapping in generic containers
- Support both direct value parameters and mapped parameters for flexibility:
  ```rust
  // Both styles should work for single-parameter actions
  node.request("service/action", "value")
  node.request("service/action", vmap!{"param" => "value"})
  ```
- Use the `vmap!` macro for parameter extraction to reduce boilerplate:
  ```rust
  // Instead of chained unwraps
  let value = data.as_ref().and_then(|v| v.as_str()).unwrap_or_default();
  
  // Use vmap! for cleaner extraction with defaults
  let value = vmap!(data, => String::new());
  ```
- Provide helpful defaults and fallbacks in your API to reduce error handling burden
- Design for both simple and advanced use cases

## Testing Philosophy

- Keep tests simple, focused, and succinct
- Each test should test one thing and test it well
- Avoid unnecessary abstractions in tests - directly test the functionality
- Don't over-engineer test code - it should be more straightforward than production code
- Question existing approaches before carrying them forward:
  - "Is this the simplest way to test this functionality?"
  - "Does this test actually test what we need to verify?"
  - "Is there a clearer way to express this test's intention?"
- Tests should be readable and maintainable - another developer should understand them immediately
- Avoid creating wrapper types or abstractions in tests unless absolutely necessary
- For new features, create comprehensive tests that cover all aspects
- Avoid test duplication - leverage existing test infrastructure when possible
- For end-to-end functionality, test the complete flow:
  - Consider testing from service endpoints
  - Simulate external systems (web UI, mobile apps) where needed
  - Test the "happy path" and error conditions
- Test both value-based and map-based parameter passing for service actions

## Verification and Documentation

After each change:

- Run all relevant tests under macro and node crates to ensure everything works as expected
  - Never change tests to make them pass (unless the tests themselves are incorrect)
  - Fix the underlying code, not the tests
- No deprecation: if you change an API, find all references and update them as well
  - We can change our API as there are no other codebases depending on this one yet
- Make documentation ready for external consumption:
  - Use the same style as other existing docs
  - Add examples
  - Include diagrams if applicable to explain:
    - Data flow
    - Process flow
    - Sequence
  - If docs already exist, update them - don't duplicate files or content
- When implementing specs from design decision files, remove the original design decision files after completion
- For security-sensitive features (like key management):
  - Document security considerations
  - Provide a security assessment with recommendations for future iterations
  - Consider interfaces with external systems (web UI, mobile apps)
  - Document the API interfaces for those external systems
- Always include code examples in documentation that match the actual implemented API patterns

## Service Macro Best Practices

- Actions should return their actual data types wrapped in `Result<T>` instead of `ServiceResponse`
- Use the `#[action]` macro to automatically handle the wrapping of returned values
- Implement proper error handling in action methods - errors will be automatically converted to error responses
- Use descriptive parameter names that match the parameters in your action handler methods
- When using subscription handlers, implement `Clone` for your service
- For event handlers, use the `vmap!` macro to extract fields with defaults
- Group related events under logical topic hierarchies
- Return native Rust types from your action handlers rather than generic JSON structures when possible
- Publish events with structured data containing all necessary context

## Avoiding Common Mistakes

- The core code (macros and node crates) need to be generic, when fixing a testing scenario dont bring deatils into the core to make teh test pass, the generic mechanism need to work or be adjusted in a genric manner.
- Don't carry over complexity just because it exists in the current code
- Question why something was done a certain way before continuing with the same approach
- Avoid "implementation-first" thinking - understand the requirements before coding
- Don't add abstraction layers without clear justification
- Keep interfaces clean and intuitive
- When fixing bugs, understand the root cause first, then fix it properly
- Watch for test focus drift - ensure tests verify the intended functionality
- Don't make users handle implementation details (like wrapping parameters or unwrapping responses)
- Avoid nested, chained method calls for data extraction - use helpers like `vmap!` instead

## Macro Development Best Practices

- Understand macros from first principles before modifying them:
  - Declarative macros (`macro_rules!`) expand to code patterns
  - Procedural macros manipulate token streams directly
- Avoid trial and error approaches when debugging macros
- Analyze generated code systematically:
  - Use `cargo expand` to see the expanded macro output
  - For procedural macros, add print statements that output the generated code:
    ```rust
    let expanded = quote! { /* ... */ };
    println!("Expanded code: {}", expanded);
    ```
  - In complex procedural macros, print intermediate representations to understand transformations
- Test macro expansions in isolation with simple test cases before using in complex code
- Common macro debugging techniques:
  - Check for hygiene issues (unintended variable capture)
  - Verify that generated identifiers are correct
  - Confirm that type information is preserved correctly
  - Ensure proper error handling and reporting
- When designing new macros:
  - Keep them as simple as possible
  - Document their behavior clearly
  - Provide clear error messages for common mistakes
  - Use helper functions to avoid duplicating code logic within macros
- For custom derive macros:
  - Check field attributes correctly
  - Handle generic types appropriately
  - Generate code that works with different visibility modifiers
- Apply tracing to see the macro execution flow:
  ```rust
  #[proc_macro_derive(MyDerive)]
  pub fn my_derive(input: TokenStream) -> TokenStream {
      eprintln!("Input: {}", input);
      // ... processing ...
      eprintln!("Output: {}", output);
      output
  }
  ```
- Design macros to make the user experience as simple as possible
- Focus on reducing boilerplate while maintaining type safety
- Create macros that generate code a developer would reasonably write by hand
- Support both simple and advanced use cases with sensible defaults
