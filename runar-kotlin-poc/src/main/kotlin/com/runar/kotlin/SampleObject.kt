package com.runar.kotlin

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor

/**
 * Sample object that will be serialized/deserialized between Kotlin and Rust
 * This matches the Rust SampleObject struct exactly
 */
@Serializable
data class SampleObject(
    val id: ULong,
    val name: String,
    val timestamp: ULong,
    val metadata: Map<String, String>,
    val values: List<Double>
) {
    companion object {
        /**
         * Create a new SampleObject with current timestamp
         */
        fun create(
            id: ULong,
            name: String,
            metadata: Map<String, String>,
            values: List<Double>
        ): SampleObject {
            return SampleObject(
                id = id,
                name = name,
                timestamp = System.currentTimeMillis() / 1000,
                metadata = metadata,
                values = values
            )
        }

        /**
         * Create an error test object
         */
        fun createErrorTest(id: ULong): SampleObject {
            return create(
                id = id,
                name = "ERROR",
                metadata = mapOf("test" to "error"),
                values = listOf(1.0)
            )
        }

        /**
         * Create a normal test object
         */
        fun createNormalTest(id: ULong): SampleObject {
            return create(
                id = id,
                name = "NORMAL",
                metadata = mapOf("test" to "normal"),
                values = listOf(1.0, 2.0, 3.0)
            )
        }
    }

    /**
     * Check if this object is an error test object
     */
    fun isErrorTest(): Boolean = name == "ERROR"

    /**
     * Serialize to CBOR bytes
     */
    fun toCborBytes(): ByteArray {
        return Cbor.encodeToByteArray(this)
    }

    /**
     * Deserialize from CBOR bytes
     */
    companion object {
        fun fromCborBytes(bytes: ByteArray): SampleObject {
            return Cbor.decodeFromByteArray(bytes)
        }
    }
}
