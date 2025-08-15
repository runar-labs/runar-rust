package com.runar.kotlin

import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets

/**
 * Transporter interface for communicating with Rust via FFI
 */
interface Transporter {
    /**
     * Initialize the transporter
     */
    fun init(): Boolean

    /**
     * Cleanup the transporter
     */
    fun cleanup(): Boolean

    /**
     * Send a request to the Rust transporter
     */
    fun request(
        topic: String,
        payloadBytes: ByteArray,
        peerNodeId: String,
        profilePublicKey: ByteArray,
        responseCallback: ResponseCallback,
        errorCallback: ErrorCallback
    ): Boolean
}

/**
 * Implementation of Transporter that communicates with Rust via FFI
 * This will be implemented using JNA to call the Rust library
 */
class RustTransporter : Transporter {
    private val logger = LoggerFactory.getLogger(RustTransporter::class.java)
    private var isInitialized = false

    // TODO: Implement JNA interface to Rust library
    // For now, this is a mock implementation

    override fun init(): Boolean {
        logger.info("Initializing Rust Transporter")
        // TODO: Call transporter_init() via JNA
        isInitialized = true
        logger.info("Rust Transporter initialized successfully")
        return true
    }

    override fun cleanup(): Boolean {
        logger.info("Cleaning up Rust Transporter")
        // TODO: Call transporter_cleanup() via JNA
        isInitialized = false
        logger.info("Rust Transporter cleaned up successfully")
        return true
    }

    override fun request(
        topic: String,
        payloadBytes: ByteArray,
        peerNodeId: String,
        profilePublicKey: ByteArray,
        responseCallback: ResponseCallback,
        errorCallback: ErrorCallback
    ): Boolean {
        if (!isInitialized) {
            logger.error("Transporter not initialized")
            errorCallback.onError(ErrorCode.UNKNOWN_ERROR.code, "Transporter not initialized")
            return false
        }

        logger.info("Sending request - Topic: $topic, Peer: $peerNodeId, Payload size: ${payloadBytes.size}")

        // TODO: Call transporter_request() via JNA
        // For now, simulate the response by calling the callback directly
        try {
            // Simulate processing delay
            Thread.sleep(100)
            
            // Check if this is an error test
            val sampleObject = SampleObject.fromCborBytes(payloadBytes)
            if (sampleObject.isErrorTest()) {
                logger.info("Received error test object, calling error callback")
                errorCallback.onError(ErrorCode.UNKNOWN_ERROR.code, "This is a test error from Kotlin")
                return true
            }

            // Simulate object modification (like Rust does)
            val modifiedObject = sampleObject.copy(
                metadata = sampleObject.metadata + mapOf(
                    "kotlin_processed" to "true",
                    "processed_at" to (System.currentTimeMillis() / 1000).toString()
                ),
                values = sampleObject.values.map { it * 2.0 }
            )

            // Serialize and send back via callback
            val modifiedBytes = modifiedObject.toCborBytes()
            logger.info("Calling response callback with ${modifiedBytes.size} bytes")
            responseCallback.onResponse(modifiedBytes)
            
            return true
        } catch (e: Exception) {
            logger.error("Request processing failed: ${e.message}")
            errorCallback.onError(ErrorCode.UNKNOWN_ERROR.code, "Request processing failed: ${e.message}")
            return false
        }
    }
}
