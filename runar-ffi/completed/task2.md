# Task 2: FFI CA API Test Implementation Plan

## 📋 **Overview**

This document outlines the comprehensive test implementation plan for the newly implemented CA API functions in the FFI layer. Based on the analysis of existing `runar-keys/tests/`, we identified significant gaps in FFI-specific testing for CA functionality.

## 🎯 **Root Cause Analysis**

### **Problem Identified**
- **FFI CA Functions**: 5 new CA functions were implemented but have **zero test coverage**
- **API Gap**: The underlying `runar-keys` API is well-tested, but FFI-specific patterns are not
- **Memory Management**: No tests for FFI handle creation/deletion patterns
- **Error Handling**: No tests for FFI error propagation in CA context

### **Functions Requiring Tests**
1. `rn_keys_ca_create_root_ca` - Create Root CA certificate
2. `rn_keys_ca_create_issuing_ca` - Create Issuing CA certificate (signed by Root CA)
3. `rn_keys_ca_get_certificate_der` - Get CA certificate DER bytes
4. `rn_keys_ca_get_certificate_subject` - Get CA certificate subject
5. `rn_keys_ca_free` - Free CA resources

## 📊 **Test Coverage Analysis**

| **Function** | **Current Status** | **Priority** | **Complexity** |
|--------------|-------------------|--------------|----------------|
| `rn_keys_ca_create_root_ca` | ❌ **No Tests** | **HIGH** | Medium |
| `rn_keys_ca_create_issuing_ca` | ❌ **No Tests** | **HIGH** | High |
| `rn_keys_ca_get_certificate_der` | ❌ **No Tests** | **MEDIUM** | Low |
| `rn_keys_ca_get_certificate_subject` | ❌ **No Tests** | **MEDIUM** | Low |
| `rn_keys_ca_free` | ❌ **No Tests** | **HIGH** | Low |

## 🧪 **Comprehensive Test Implementation Plan**

### **Phase 0: E2E Integration Tests (Mirror of Transport E2E)**

#### **0.1 FFI E2E Integration Test Enhancement**
**File**: `tests/ffi_e2e_integration_test.rs`

Based on the successful implementation in `runar-transporter/tests/full_transport_e2e_test.rs`, we need to add the following phases to the FFI E2E test to ensure complete parity:

```rust
// Additional Phases to Add to FFI E2E Test:

// ==========================================
// Phase 13: CA Reconstruction Validation
// ==========================================
#[test]
fn test_ffi_ca_reconstruction_validation() {
    // Test reconstruction of the issuing CA using from_existing() via FFI
    // 1. Create root CA via FFI
    // 2. Create issuing CA via FFI
    // 3. Reconstruct issuing CA using from_existing() via FFI
    // 4. Verify reconstructed CA is identical
    // 5. Test that reconstructed CA can sign certificates
}

// ==========================================
// Phase 14: Reconstruction with QUIC Server
// ==========================================
#[test]
fn test_ffi_reconstruction_with_quic_server() {
    // 1. Stop existing QUIC server
    // 2. Create new CA Node with reconstructed CA via FFI
    // 3. Start new QUIC server with reconstructed CA Node
    // 4. Verify server starts successfully
}

// ==========================================
// Phase 15: Basic Operations with Reconstructed CA
// ==========================================
#[test]
fn test_ffi_basic_operations_with_reconstructed_ca() {
    // 1. Create new mobile node for testing
    // 2. Test basic enrollment with reconstructed CA via FFI
    // 3. Test basic status request via FFI
    // 4. Verify all operations work correctly
}
```

#### **0.2 FFI CA API Functions for Reconstruction**
**Functions to Test**:
- `rn_keys_ca_create_root_ca` - Create Root CA certificate
- `rn_keys_ca_create_issuing_ca` - Create Issuing CA certificate (signed by Root CA)
- `rn_keys_ca_get_certificate_der` - Get CA certificate DER bytes
- `rn_keys_ca_get_certificate_subject` - Get CA certificate subject
- `rn_keys_ca_free` - Free CA resources

#### **0.3 FFI E2E Test Structure**
**Current Phases** (1-12): ✅ **Already Implemented**
- Phase 1: Setup
- Phase 2: CA Node and Server
- Phase 3: Mobile Node CSR and Enrollment
- Phase 4: Certificate Renewal
- Phase 5: Certificate Revocation + CRL-lite
- Phase 6: Status and Chain
- Phase 7: Profile Key Functionality
- Phase 8: Rate Limiting
- Phase 9: Token Revocation
- Phase 10: Negative Cases
- Phase 11: Error Handling
- Phase 12: Cleanup

**New Phases** (13-15): 🔄 **To Be Implemented**
- Phase 13: CA Reconstruction Validation
- Phase 14: Reconstruction with QUIC Server
- Phase 15: Basic Operations with Reconstructed CA

### **Phase 1: Unit Tests for Individual Functions**

#### **1.1 Root CA Creation Tests**
**File**: `tests/ca_creation_unit_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_create_root_ca_happy_path() {
    // Test successful root CA creation with valid subject
    // Verify handle is created and not null
    // Verify error code is 0
}

#[test]
fn test_ca_create_root_ca_null_arguments() {
    // Test null subject pointer
    // Test null output pointer
    // Test null error pointer
    // Verify RN_ERROR_NULL_ARGUMENT is returned
}

#[test]
fn test_ca_create_root_ca_invalid_utf8() {
    // Test invalid UTF-8 in subject string
    // Verify RN_ERROR_INVALID_UTF8 is returned
}

#[test]
fn test_ca_create_root_ca_creation_failure() {
    // Test CA creation failure scenarios
    // Verify RN_ERROR_OPERATION_FAILED is returned
}
```

#### **1.2 Issuing CA Creation Tests**
**File**: `tests/ca_creation_unit_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_create_issuing_ca_happy_path() {
    // Test successful issuing CA creation
    // Verify root CA is used for signing
    // Verify handle is created and not null
    // Verify error code is 0
}

#[test]
fn test_ca_create_issuing_ca_null_arguments() {
    // Test null root_ca pointer
    // Test null subject pointer
    // Test null output pointer
    // Test null error pointer
    // Verify RN_ERROR_NULL_ARGUMENT is returned
}

#[test]
fn test_ca_create_issuing_ca_invalid_utf8() {
    // Test invalid UTF-8 in subject string
    // Verify RN_ERROR_INVALID_UTF8 is returned
}

#[test]
fn test_ca_create_issuing_ca_key_generation_failure() {
    // Test EcdsaKeyPair::new() failure
    // Verify RN_ERROR_OPERATION_FAILED is returned
}

#[test]
fn test_ca_create_issuing_ca_csr_creation_failure() {
    // Test CertificateRequest::create() failure
    // Verify RN_ERROR_OPERATION_FAILED is returned
}

#[test]
fn test_ca_create_issuing_ca_signing_failure() {
    // Test sign_ca_certificate_request_with_serial() failure
    // Verify RN_ERROR_OPERATION_FAILED is returned
}
```

#### **1.3 Certificate Getter Tests**
**File**: `tests/ca_getter_unit_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_get_certificate_der_happy_path() {
    // Test successful DER retrieval
    // Verify DER bytes are not empty
    // Verify error code is 0
}

#[test]
fn test_ca_get_certificate_der_null_arguments() {
    // Test null ca pointer
    // Test null output pointer
    // Test null error pointer
    // Verify RN_ERROR_NULL_ARGUMENT is returned
}

#[test]
fn test_ca_get_certificate_der_memory_allocation_failure() {
    // Test alloc_bytes failure
    // Verify RN_ERROR_MEMORY_ALLOCATION is returned
}

#[test]
fn test_ca_get_certificate_subject_happy_path() {
    // Test successful subject retrieval
    // Verify subject string is valid
    // Verify error code is 0
}

#[test]
fn test_ca_get_certificate_subject_null_arguments() {
    // Test null ca pointer
    // Test null output pointer
    // Test null error pointer
    // Verify RN_ERROR_NULL_ARGUMENT is returned
}

#[test]
fn test_ca_get_certificate_subject_invalid_utf8() {
    // Test invalid UTF-8 in subject
    // Verify RN_ERROR_INVALID_UTF8 is returned
}
```

#### **1.4 CA Free Tests**
**File**: `tests/ca_memory_unit_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_free_happy_path() {
    // Test successful CA handle freeing
    // Verify no crashes or memory leaks
}

#[test]
fn test_ca_free_null_handle() {
    // Test freeing null handle
    // Verify no crashes (should be safe)
}

#[test]
fn test_ca_free_double_free() {
    // Test double-free scenario
    // Verify no crashes (should be safe)
}
```

### **Phase 2: Integration Tests**

#### **2.1 Complete CA Workflow Tests**
**File**: `tests/ca_workflow_integration_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_complete_ca_hierarchy_workflow() {
    // 1. Create root CA
    // 2. Create issuing CA signed by root CA
    // 3. Get certificates from both CAs
    // 4. Verify certificate chain
    // 5. Free all resources
    // Verify complete workflow works end-to-end
}

#[test]
fn test_ca_certificate_chain_validation() {
    // 1. Create root CA
    // 2. Create issuing CA
    // 3. Verify issuing CA is signed by root CA
    // 4. Verify certificate extensions are correct
    // 5. Verify SKI/AKI relationships
}

#[test]
fn test_ca_memory_management_workflow() {
    // 1. Create multiple CAs
    // 2. Use them in various operations
    // 3. Free them in different orders
    // 4. Verify no memory leaks or crashes
}
```

#### **2.2 Error Handling Integration Tests**
**File**: `tests/ca_error_integration_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_error_propagation_chain() {
    // Test error propagation through multiple function calls
    // Verify error codes are consistent
    // Verify error messages are meaningful
}

#[test]
fn test_ca_handle_validation_chain() {
    // Test handle validation across multiple operations
    // Verify invalid handles are properly rejected
    // Verify error codes are appropriate
}
```

### **Phase 3: Memory Management Tests**

#### **3.1 Handle Lifecycle Tests**
**File**: `tests/ca_memory_lifecycle_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_handle_creation_and_cleanup() {
    // Test handle creation patterns
    // Test cleanup patterns
    // Verify memory is properly managed
}

#[test]
fn test_ca_handle_reuse_patterns() {
    // Test reusing handles after operations
    // Test handle state consistency
    // Verify no memory corruption
}

#[test]
fn test_ca_handle_concurrent_access() {
    // Test concurrent access to CA handles
    // Verify thread safety
    // Verify no race conditions
}
```

#### **3.2 Memory Allocation Tests**
**File**: `tests/ca_memory_allocation_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_memory_allocation_failure_scenarios() {
    // Test alloc_bytes failure scenarios
    // Test memory allocation edge cases
    // Verify proper error handling
}

#[test]
fn test_ca_memory_deallocation_patterns() {
    // Test various deallocation patterns
    // Test memory leak detection
    // Verify proper cleanup
}
```

### **Phase 4: Edge Case and Stress Tests**

#### **4.1 Edge Case Tests**
**File**: `tests/ca_edge_cases_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_very_long_subject() {
    // Test CA creation with very long subject strings
    // Verify proper handling
}

#[test]
fn test_ca_special_characters_subject() {
    // Test CA creation with special characters
    // Verify proper UTF-8 handling
}

#[test]
fn test_ca_unicode_subject() {
    // Test CA creation with Unicode characters
    // Verify proper Unicode handling
}

#[test]
fn test_ca_extreme_validity_periods() {
    // Test CA creation with extreme validity periods
    // Verify proper handling
}
```

#### **4.2 Stress Tests**
**File**: `tests/ca_stress_test.rs`

```rust
// Test Cases Required:
#[test]
fn test_ca_creation_stress() {
    // Test creating many CAs in sequence
    // Verify memory usage is reasonable
    // Verify no memory leaks
}

#[test]
fn test_ca_operations_stress() {
    // Test many operations on same CA
    // Verify handle remains valid
    // Verify no memory corruption
}
```

## 🔧 **Implementation Guidelines**

### **Test Structure Standards**
1. **File Organization**: Group related tests in dedicated files
2. **Naming Convention**: Use descriptive test names with `test_ca_` prefix
3. **Error Testing**: Always test both success and failure paths
4. **Memory Testing**: Include memory management verification
5. **Documentation**: Add comprehensive test documentation

### **Test Data Standards**
1. **Test Subjects**: Use consistent test subject strings
2. **Test Validity**: Use reasonable validity periods (365 days)
3. **Test Serials**: Use predictable serial numbers for testing
4. **Test Networks**: Use consistent test network IDs

### **Assertion Standards**
1. **Error Codes**: Verify specific error codes are returned
2. **Handle Validation**: Verify handles are created/destroyed properly
3. **Memory Validation**: Verify no memory leaks or corruption
4. **Data Validation**: Verify certificate data is correct

## 📈 **Success Metrics**

### **Coverage Targets**
- **Function Coverage**: 100% of CA functions tested
- **Branch Coverage**: 100% of error paths tested
- **Memory Coverage**: 100% of memory management paths tested
- **Integration Coverage**: 100% of workflow combinations tested

### **Quality Targets**
- **No Memory Leaks**: All tests must pass memory leak detection
- **No Crashes**: All tests must complete without crashes
- **Proper Error Handling**: All error paths must be tested
- **Documentation**: All tests must be well-documented

## 🚀 **Implementation Timeline**

### **Week 1: E2E Integration Tests (Priority)**
- Day 1-2: Add Phase 13 (CA Reconstruction Validation) to FFI E2E test
- Day 3-4: Add Phase 14 (Reconstruction with QUIC Server) to FFI E2E test
- Day 5: Add Phase 15 (Basic Operations with Reconstructed CA) to FFI E2E test

### **Week 2: Unit Tests**
- Day 1-2: Root CA creation tests
- Day 3-4: Issuing CA creation tests
- Day 5: Certificate getter tests

### **Week 3: Integration Tests**
- Day 1-2: Complete workflow tests
- Day 3-4: Error handling tests
- Day 5: Memory management tests

### **Week 4: Edge Cases and Stress Tests**
- Day 1-2: Edge case tests
- Day 3-4: Stress tests
- Day 5: Final validation and documentation

## 📝 **Dependencies**

### **Required Test Infrastructure**
1. **Memory Testing**: Valgrind or similar memory leak detection
2. **Error Testing**: Comprehensive error scenario simulation
3. **Integration Testing**: Full workflow testing framework
4. **Documentation**: Test documentation standards

### **Required Test Data**
1. **Test Certificates**: Pre-generated test certificates
2. **Test Keys**: Pre-generated test key pairs
3. **Test Subjects**: Standardized test subject strings
4. **Test Networks**: Standardized test network configurations

## 🎯 **Expected Outcomes**

### **Immediate Benefits**
1. **Complete Test Coverage**: All CA functions will have comprehensive tests
2. **Memory Safety**: All memory management patterns will be validated
3. **Error Handling**: All error paths will be tested and documented
4. **Integration Validation**: All workflow combinations will be verified

### **Long-term Benefits**
1. **Regression Prevention**: Future changes will be validated against comprehensive tests
2. **Documentation**: Tests will serve as living documentation of CA API usage
3. **Confidence**: High confidence in CA API reliability and safety
4. **Maintainability**: Easier maintenance and debugging of CA functionality

## 🔍 **Validation Criteria**

### **Test Completion Criteria**
- [ ] **E2E Integration Tests**: FFI E2E test mirrors transport E2E test with all phases (1-15)
- [ ] **CA Reconstruction**: Phase 13-15 implemented in FFI E2E test
- [ ] All 5 CA functions have comprehensive unit tests
- [ ] All error paths are tested and documented
- [ ] All memory management patterns are validated
- [ ] All integration workflows are tested
- [ ] All edge cases and stress scenarios are covered
- [ ] All tests pass consistently
- [ ] All tests are well-documented
- [ ] Memory leak detection passes
- [ ] Code coverage targets are met

### **Quality Assurance Criteria**
- [ ] No memory leaks detected
- [ ] No crashes or undefined behavior
- [ ] All error codes are properly tested
- [ ] All handle lifecycle patterns are validated
- [ ] All certificate data is properly validated
- [ ] All UTF-8 handling is properly tested
- [ ] All memory allocation patterns are tested
- [ ] All concurrent access patterns are validated

---

## ✅ **E2E INTEGRATION PARTIALLY COMPLETE**

### **📊 E2E Test Results Summary**
- **FFI E2E Test**: Successfully enhanced with Phases 13-15 ✅
- **Phase 13 (CA Reconstruction Validation)**: ✅ **COMPLETE** - All FFI CA APIs working correctly
- **Phase 14 (Reconstruction with QUIC Server)**: ❌ **CRASHING** - SIGSEGV during server creation
- **Phase 15 (Basic Operations with Reconstructed CA)**: ⏸️ **PENDING** - Blocked by Phase 14 crash

### **🧪 E2E Integration Details**
- **Location**: `runar-ffi/tests/ffi_e2e_integration_test.rs`
- **Approach**: Added reconstruction scenario at the end after all current flow is complete
- **Phases Added**:
  - **Phase 13**: CA Reconstruction Validation ✅
    - `rn_keys_ca_create_root_ca` ✅
    - `rn_keys_ca_create_issuing_ca` ✅
    - `rn_keys_ca_get_certificate_der` ✅
    - `rn_keys_ca_get_certificate_subject` ✅
    - `rn_keys_ca_free` ✅
  - **Phase 14**: Reconstruction with QUIC Server ❌
    - Server stop/start sequence causing SIGSEGV
  - **Phase 15**: Basic Operations with Reconstructed CA ⏸️
    - Blocked by Phase 14 crash

### **🔍 Issue Analysis**
- **Root Cause**: SIGSEGV during Phase 14 server reconstruction
- **Location**: After stopping existing server, during new server creation
- **Likely Cause**: Memory management issue with server handles or CA Node references
- **Impact**: Phases 14-15 cannot complete until resolved

### **📋 Next Steps**
1. **Debug Phase 14 SIGSEGV**: Investigate memory management in server reconstruction
2. **Fix Memory Issues**: Ensure proper cleanup and handle management
3. **Complete Phase 15**: Test basic operations with reconstructed CA
4. **Validate Full E2E**: Ensure all phases work together

**Status**: 🔄 **E2E INTEGRATION IN PROGRESS**  
**Priority**: 🔴 **HIGH**  
**Estimated Effort**: 3 weeks  
**Dependencies**: None  
**Blockers**: Phase 14 SIGSEGV crash
