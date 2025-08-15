package com.runar.kotlin

/**
 * Error codes for FFI communication
 * These must match the Rust ErrorCode enum exactly
 */
enum class ErrorCode(val code: UInt) {
    SUCCESS(0u),
    INVALID_POINTER(1u),
    SERIALIZATION_ERROR(2u),
    DESERIALIZATION_ERROR(3u),
    INVALID_DATA(4u),
    CALLBACK_ERROR(5u),
    UNKNOWN_ERROR(99u);

    companion object {
        /**
         * Get ErrorCode from numeric code
         */
        fun fromCode(code: UInt): ErrorCode {
            return values().find { it.code == code } ?: UNKNOWN_ERROR
        }
    }
}
