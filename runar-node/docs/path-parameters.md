# Path Parameters Handling

## Overview

This document describes the approach for handling path parameters in service handlers within the system.

## Architectural Principles

1. **Proper Architectural Boundaries**: 
   - Path parameter extraction is the responsibility of the router (ServiceRegistry)
   - Services should only work with pre-extracted parameters, not manually parse paths

2. **Single Source of Truth**:
   - Parameters should be extracted exactly once, by the router
   - All components should reference the same extracted parameters

3. **Clean Error Handling**:
   - Missing parameters should trigger clear error responses
   - Error messages should be specific and actionable

## Implementation

### Path Matching and Parameter Extraction

Path templates can include parameter placeholders in the format `{parameter_name}`. For example:
- `services/{service_path}`
- `services/{service_path}/state`
- `services/{service_type}/actions/{action_name}`

When a request is made with a path matching the template pattern, the ServiceRegistry's `get_action_handler` method:
1. First checks for an exact match with the path
2. If no direct match is found, checks for template patterns
3. For templates, matches segment by segment, treating `{parameter_name}` segments as wildcards
4. When a match is found, extracts parameter values and stores them in `context.path_params`

### Service Handler Implementation

Services should follow these guidelines when working with path parameters:

1. **Parameter Access**:
   ```rust
   // Correct way to access path parameters
   match ctx.path_params.get("parameter_name").cloned() {
       Some(value) => {
           // Process the parameter
       },
       None => {
           // Return an error response for missing parameter
           return ServiceResponse::error(400, "Missing required parameter");
       }
   }
   ```

2. **Error Handling**:
   - Always check for parameter existence
   - Return clear error messages when parameters are missing
   - Use appropriate HTTP status codes (400 for missing parameters)

3. **Logging**:
   - Log path parameter access for debugging
   - Include parameter values in debug logs

### Anti-Patterns to Avoid

1. **Manual Path Parsing**:
   - Do not manually parse `topic_path` to extract parameters
   - Rely on the router to handle parameter extraction

2. **Silent Failure**:
   - Do not use default values without logging a warning
   - Missing required parameters should be treated as errors

3. **Multiple Sources of Truth**:
   - Avoid checking both `path_params` and manually parsing the path
   - Using both approaches can lead to inconsistencies

## Testing

For comprehensive testing of path parameters:

1. **Register Template Paths**: Register handlers with path templates containing parameters
2. **Test Exact Matches**: Test exact paths that should match templates
3. **Test Parameter Extraction**: Verify parameter values are correctly extracted
4. **Test Non-Matches**: Test paths that should not match templates
5. **Test Edge Cases**: Test paths with missing or extra segments

## Conclusion

By centralizing path parameter extraction in the router and having services rely on pre-extracted parameters, we maintain clean architectural boundaries and avoid inconsistencies. This approach provides a foundation for reliable and maintainable path-based routing throughout the system. 