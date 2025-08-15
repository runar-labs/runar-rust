# Kotlin-Rust FFI POC

This project demonstrates Foreign Function Interface (FFI) communication between Kotlin and Rust using a simplified transporter interface. The goal is to validate bidirectional data serialization/deserialization using CBOR format.

## 🏗️ Project Structure

```
runar-kotlin-poc/
├── build.gradle.kts           # Gradle build configuration
├── settings.gradle.kts        # Gradle settings
├── gradle.properties          # Gradle properties
├── src/
│   ├── main/
│   │   ├── kotlin/
│   │   │   └── com/runar/kotlin/
│   │   │       ├── SampleObject.kt      # Data class matching Rust struct
│   │   │       ├── ErrorCode.kt         # Error codes enum
│   │   │       ├── Callbacks.kt         # Callback interfaces
│   │   │       ├── Transporter.kt       # Transporter interface & implementation
│   │   │       └── Main.kt              # Main application
│   │   └── resources/
│   │       └── logback.xml              # Logging configuration
│   └── test/
│       └── kotlin/
│           └── com/runar/kotlin/
│               ├── SampleObjectTest.kt   # Unit tests for SampleObject
│               └── TransporterTest.kt    # Unit tests for Transporter
└── README.md                  # This file
```

## 🚀 Features

### Core Components
- **SampleObject**: Data class that matches the Rust `SampleObject` struct exactly
- **CBOR Integration**: Full serialization/deserialization using `kotlinx-serialization-cbor`
- **Error Handling**: Comprehensive error codes and callback-based error reporting
- **Transporter Interface**: Clean abstraction for FFI communication
- **Callback System**: Response and error callback interfaces for async communication

### Data Flow
1. **Kotlin** creates a `SampleObject` instance
2. **Kotlin** serializes to CBOR bytes using Kotlin CBOR library
3. **Kotlin** calls Rust transporter via FFI (currently mocked)
4. **Kotlin** receives modified data via callback
5. **Kotlin** deserializes and validates the response

## 🛠️ Prerequisites

- Java 11 or higher
- Gradle 7.0 or higher
- Kotlin 1.9.0 or higher

## 📦 Dependencies

- **Kotlin**: Standard library and serialization
- **CBOR**: `kotlinx-serialization-cbor` for data serialization
- **Logging**: SLF4J + Logback for comprehensive logging
- **Testing**: Kotlin test framework with coroutines support
- **JNA**: For future native library integration

## 🏃‍♂️ Quick Start

### Prerequisites
Before building, ensure you have:
- Java 11 or higher
- Maven 3.6+ or Gradle 7.0+
- Kotlin 1.9.0+

### Option 1: Maven Build
```bash
# Clean and compile
mvn clean compile

# Run tests
mvn test

# Run application
mvn exec:java

# Package
mvn package
```

### Option 2: Gradle Build
```bash
# Clean and build
./gradlew clean build

# Run tests
./gradlew test

# Run application
./gradlew run

# Package
./gradlew jar
```

**Note**: If you don't have Maven or Gradle installed, you can install them using:
- **Maven**: `brew install maven` (macOS) or download from https://maven.apache.org/
- **Gradle**: `brew install gradle` (macOS) or download from https://gradle.org/

## 🔧 Configuration

### Logging
The application uses Logback for logging configuration. Logs are written to both console and file:
- Console: Human-readable format with timestamps
- File: Detailed logs saved to `logs/runar-kotlin-poc.log`

### CBOR Serialization
CBOR serialization is handled by `kotlinx-serialization-cbor` with automatic code generation for the `SampleObject` class.

## 📋 API Reference

### SampleObject
```kotlin
@Serializable
data class SampleObject(
    val id: ULong,
    val name: String,
    val timestamp: ULong,
    val metadata: Map<String, String>,
    val values: List<Double>
)
```

**Factory Methods:**
- `SampleObject.create(id, name, metadata, values)` - Create with current timestamp
- `SampleObject.createErrorTest(id)` - Create error test object
- `SampleObject.createNormalTest(id)` - Create normal test object

**Utility Methods:**
- `isErrorTest()` - Check if object is an error test
- `toCborBytes()` - Serialize to CBOR
- `fromCborBytes(bytes)` - Deserialize from CBOR

### Transporter Interface
```kotlin
interface Transporter {
    fun init(): Boolean
    fun cleanup(): Boolean
    fun request(
        topic: String,
        payloadBytes: ByteArray,
        peerNodeId: String,
        profilePublicKey: ByteArray,
        responseCallback: ResponseCallback,
        errorCallback: ErrorCallback
    ): Boolean
}
```

### Callbacks
```kotlin
interface ResponseCallback {
    fun onResponse(payloadBytes: ByteArray)
}

interface ErrorCallback {
    fun onError(errorCode: UInt, errorMessage: String)
}
```

## 🧪 Testing

### Unit Tests
The project includes comprehensive unit tests covering:
- Object creation and modification
- CBOR serialization/deserialization
- Error detection and handling
- Transporter workflow
- Edge cases and error conditions

### Test Execution
```bash
# Run all tests
./gradlew test

# Run specific test class
./gradlew test --tests SampleObjectTest

# Run with debug output
./gradlew test --info
```

## 🔄 Integration with Rust

### Current Status
The Kotlin implementation currently includes a mock transporter that simulates the Rust behavior. This allows for:
- Complete testing of the Kotlin side
- Validation of CBOR serialization/deserialization
- Verification of the callback system
- Testing of error handling scenarios

### Next Steps for Rust Integration
1. **JNA Interface**: Implement JNA bindings to the Rust library
2. **Native Library Loading**: Load the compiled Rust library
3. **FFI Function Calls**: Call the actual Rust functions
4. **Integration Testing**: End-to-end testing with real Rust backend

### Rust Library Requirements
The Rust library must provide these FFI functions:
- `transporter_init()` - Initialize the transporter
- `transporter_cleanup()` - Cleanup resources
- `transporter_request()` - Process requests and call callbacks

## 📊 Error Handling

### Error Codes
The implementation supports all error codes defined in the Rust `ErrorCode` enum:
- `SUCCESS(0)` - Operation completed successfully
- `INVALID_POINTER(1)` - Invalid pointer parameters
- `SERIALIZATION_ERROR(2)` - CBOR serialization failure
- `DESERIALIZATION_ERROR(3)` - CBOR deserialization failure
- `INVALID_DATA(4)` - Invalid data format
- `CALLBACK_ERROR(5)` - Callback execution failure
- `UNKNOWN_ERROR(99)` - Unexpected error

### Error Propagation
Errors are propagated through the callback system, allowing the application to:
- Log detailed error information
- Handle errors gracefully
- Provide user feedback
- Implement retry logic if needed

## 🚀 Performance Considerations

### CBOR Serialization
- Uses efficient binary format
- Minimal memory overhead
- Fast serialization/deserialization
- Compact data representation

### Memory Management
- Automatic garbage collection
- Efficient ByteArray handling
- Minimal object allocation
- Proper resource cleanup

## 🔍 Debugging

### Logging Levels
- **DEBUG**: Detailed execution flow
- **INFO**: Important milestones and data
- **WARN**: Potential issues
- **ERROR**: Error conditions and failures

### Debug Output
Enable debug logging by modifying `logback.xml`:
```xml
<logger name="com.runar.kotlin" level="DEBUG" />
```

## 🤝 Contributing

### Code Style
- Follow Kotlin coding conventions
- Use meaningful variable and function names
- Add comprehensive documentation
- Include unit tests for new functionality

### Testing Requirements
- All new code must include unit tests
- Tests must pass before merging
- Maintain test coverage above 90%
- Include integration tests for complex workflows

## 📝 License

This project is part of the Runar ecosystem and follows the same licensing terms.

## 🔗 Related Projects

- **runar-poc-ffi**: Rust implementation of the FFI interface
- **runar-common**: Shared utilities and types
- **runar-serializer**: Serialization framework

## 📞 Support

For questions and support:
- Check the test suite for usage examples
- Review the logging output for debugging
- Consult the Rust implementation documentation
- Open an issue for bugs or feature requests
