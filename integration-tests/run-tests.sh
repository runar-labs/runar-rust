#!/bin/bash

# Cross-Platform QUIC Transport Integration Test Suite
# Tests communication between Rust and Swift QUIC transport implementations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_TIMEOUT=300  # 5 minutes
LOG_DIR="$SCRIPT_DIR/test-logs"
RESULTS_DIR="$SCRIPT_DIR/test-results"

# Create directories
mkdir -p "$LOG_DIR" "$RESULTS_DIR"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_DIR/test-run.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_DIR/test-run.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_DIR/test-run.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_DIR/test-run.log"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Stop Docker Compose services
    if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
        cd "$SCRIPT_DIR"
        docker-compose down --remove-orphans --volumes
    fi
    
    # Kill any remaining processes
    pkill -f "rust-transport-test" || true
    pkill -f "SwiftTransportTest" || true
    
    log_info "Cleanup completed"
}

# Set up trap for cleanup
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Build test images
build_images() {
    log_info "Building test images..."
    
    cd "$SCRIPT_DIR"
    
    # Build Swift transport image
    log_info "Building Swift transport image..."
    docker build -f Dockerfile.swift-transport -t swift-quic-transport:test ../swift-transporter
    
    # Build Rust transport image
    log_info "Building Rust transport image..."
    docker build -f Dockerfile.rust-transport -t rust-quic-transport:test ../runar-rust
    
    # Build test coordinator image
    log_info "Building test coordinator image..."
    docker build -f Dockerfile.test-coordinator -t test-coordinator:test .
    
    log_success "All images built successfully"
}

# Run Docker Compose tests
run_docker_tests() {
    log_info "Starting Docker Compose test environment..."
    
    cd "$SCRIPT_DIR"
    
    # Start services
    docker-compose up -d --build
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Check service health
    check_service_health
    
    # Run test coordinator
    log_info "Running test coordinator..."
    docker-compose exec -T test-coordinator cargo run --bin test-coordinator \
        -- --timeout 60 \
        --rust-url "http://rust-transport:50001" \
        --swift-url "http://swift-transport:50003" \
        --output-file "/app/test-results/results.json"
    
    # Copy results
    docker cp test-coordinator:/app/test-results/results.json "$RESULTS_DIR/"
    
    log_success "Docker tests completed"
}

# Check service health
check_service_health() {
    log_info "Checking service health..."
    
    # Check Rust transport
    if docker-compose exec -T rust-transport curl -f http://localhost:50001/health; then
        log_success "Rust transport is healthy"
    else
        log_error "Rust transport health check failed"
        return 1
    fi
    
    # Check Swift transport
    if docker-compose exec -T swift-transport curl -f http://localhost:50003/health; then
        log_success "Swift transport is healthy"
    else
        log_error "Swift transport health check failed"
        return 1
    fi
}

# Run local tests (alternative to Docker)
run_local_tests() {
    log_info "Running local tests..."
    
    # This would run tests directly on the host
    # Useful for development and debugging
    
    log_warning "Local tests not implemented yet"
}

# Analyze test results
analyze_results() {
    log_info "Analyzing test results..."
    
    if [ -f "$RESULTS_DIR/results.json" ]; then
        # Parse and display results
        python3 -c "
import json
import sys

try:
    with open('$RESULTS_DIR/results.json', 'r') as f:
        results = json.load(f)
    
    total = len(results)
    passed = sum(1 for r in results if r['success'])
    failed = total - passed
    
    print(f'Test Results Summary:')
    print(f'Total tests: {total}')
    print(f'Passed: {passed}')
    print(f'Failed: {failed}')
    
    if failed > 0:
        print('\\nFailed tests:')
        for result in results:
            if not result['success']:
                print(f'  - {result[\"test_id\"]}: {result[\"errors\"]}')
        sys.exit(1)
    else:
        print('\\n✅ All tests passed!')
        sys.exit(0)
        
except Exception as e:
    print(f'Error analyzing results: {e}')
    sys.exit(1)
"
    else
        log_error "No test results found"
        return 1
    fi
}

# Generate test report
generate_report() {
    log_info "Generating test report..."
    
    local report_file="$RESULTS_DIR/test-report.md"
    
    cat > "$report_file" << EOF
# Cross-Platform QUIC Transport Test Report

Generated: $(date)

## Test Environment

- **Rust Transport**: Quinn 0.11.x with rustls
- **Swift Transport**: Network.framework QUIC
- **Test Coordinator**: Rust-based orchestration
- **Network**: Docker bridge network

## Test Results

EOF

    if [ -f "$RESULTS_DIR/results.json" ]; then
        python3 -c "
import json
import sys

with open('$RESULTS_DIR/results.json', 'r') as f:
    results = json.load(f)

total = len(results)
passed = sum(1 for r in results if r['success'])
failed = total - passed

print(f'- **Total Tests**: {total}')
print(f'- **Passed**: {passed}')
print(f'- **Failed**: {failed}')
print(f'- **Success Rate**: {(passed/total*100):.1f}%')

print('\\n## Test Details\\n')

for result in results:
    status = '✅ PASS' if result['success'] else '❌ FAIL'
    print(f'### {result[\"test_id\"]} - {status}')
    print(f'- **Duration**: {result[\"duration_ms\"]}ms')
    print(f'- **Timestamp**: {result[\"timestamp\"]}')
    
    if result['errors']:
        print('- **Errors**:')
        for error in result['errors']:
            print(f'  - {error}')
    
    print()
"
    fi >> "$report_file"
    
    log_success "Test report generated: $report_file"
}

# Main test execution
main() {
    log_info "Starting Cross-Platform QUIC Transport Integration Tests"
    log_info "========================================================"
    
    # Parse command line arguments
    local test_mode="docker"
    while [[ $# -gt 0 ]]; do
        case $1 in
            --local)
                test_mode="local"
                shift
                ;;
            --docker)
                test_mode="docker"
                shift
                ;;
            --help)
                echo "Usage: $0 [--local|--docker]"
                echo "  --local   Run tests locally (development)"
                echo "  --docker  Run tests in Docker (default)"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run tests based on mode
    case $test_mode in
        "docker")
            check_prerequisites
            build_images
            run_docker_tests
            ;;
        "local")
            run_local_tests
            ;;
    esac
    
    # Analyze and report results
    analyze_results
    generate_report
    
    log_success "Test suite completed successfully!"
}

# Run main function
main "$@" 