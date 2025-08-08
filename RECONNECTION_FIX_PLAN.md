# Node Reconnection Fix Plan

## Problem Statement

**Core Issue**: In the replication test `test_full_replication_between_nodes`, when Node 1 is stopped and restarted, it cannot properly reconnect to the network and sync missed operations.

**Specific Failure**: 
- Node 1, Node 2, and Node 3 are running with SQLite replication
- Node 1 is stopped while Node 2 and Node 3 continue operations
- Node 2 and Node 3 perform UPDATE/DELETE operations while Node 1 is down
- When Node 1 restarts, it fails to sync the missed operations
- **Test to verify**: `test_node_stop_restart_reconnection` in `runar-node-tests/src/network/remote_test.rs`

## Root Cause Analysis

### Current Behavior (Broken)
1. Node 1 stops - transport tasks exit but peers remain in discovery system
2. Node 2 and Node 3 continue operations but don't know Node 1 is gone
3. Node 1 restarts and announces itself via multicast
4. Node 2 and Node 3 receive the announcement but treat it as "existing peer" and skip reconnection
5. Result: Node 1 never gets the missed operations

### Why Current Discovery Fails
- **Discovery system**: Only removes peers from `discovered_nodes` when explicit goodbye messages are received
- **Transport layer**: When connection tasks exit, only cleans up internal `peers` map
- **No coordination**: Transport doesn't notify discovery when peers disconnect
- **Race conditions**: Goodbye messages create timing issues

## Requirements

### Functional Requirements
1. **Connection Failure Detection**: When a transport connection fails, the system must detect this immediately
2. **Comprehensive Cleanup**: Failed peer must be removed from transport, discovery, and node layers
3. **Restart Recognition**: When a node restarts, other nodes must treat it as a new peer requiring fresh connection (THIS WILL occurs naturaly when req 1 aND2 WORKS AS EPCTECTED.. SO NOTHING NEW NEEDED FOR THIS.)
4. **Synchronous Processing**: All cleanup must happen in the same task/thread to avoid race conditions
5. **No New Tasks**: Must not spawn additional async tasks for cleanup

CAREFUL TO NOT BREAK EXISTING functinality.. use the existing tests  int he crate runar-node-tests to check your changes and progress bhave no broken other areas.

Specialy yhe tranpsorter which is already robust.. and this change will impact the transporter.. make sure no existing behaviour is broken

NO Backwares compatility.. this is a new codebase. so any API changes needs to be done and changes in the places that are impactd.. no shortcuts.. no hacks..no simplifications.

Think from first principles.. Think wide and think deep.

Behave as an expert Rust programmer and expert network programmer. experte peer to peer programger.

Testing:
test_remote_action_call() is your baseline.. make sure continue working after all changes..

test_node_stop_restart_reconnection() was created to demostrate this issue.. so your chagnes can be tested with this test...

ONLY change tests if you chagne API and the test need to align.. otherwise DO NOT CAHNGE ANYTHIGN else in the test.. the node config and etc.. all work for all our network tests.. so that is not an issue.. if u face issues it is related to your changges.. DO NOT HACK the tests..


### Technical Requirements
1. **Follow Existing Patterns**: Use existing codebase logging and error handling patterns
3. **Same Thread Execution**: All peer removal logic in the connection task that detects the failure
4. **Proper Logging**: Use `logger.info()`, `logger.error()` etc., not `eprintln!` or `tracing::`
