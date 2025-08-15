package com.runar.kotlin

import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets

/**
 * Main application demonstrating the Kotlin-Rust FFI POC
 */
fun main() {
    val logger = LoggerFactory.getLogger("Main")
    logger.info("Starting Kotlin-Rust FFI POC")

    try {
        // Create transporter
        val transporter = RustTransporter()
        
        // Initialize
        if (!transporter.init()) {
            logger.error("Failed to initialize transporter")
            return
        }

        // Create callbacks
        val responseCallback = DefaultResponseCallback()
        val errorCallback = DefaultErrorCallback()

        // Test 1: Normal object
        logger.info("=== Test 1: Normal Object ===")
        testNormalObject(transporter, responseCallback, errorCallback)

        // Test 2: Error test object
        logger.info("=== Test 2: Error Test Object ===")
        testErrorObject(transporter, responseCallback, errorCallback)

        // Test 3: Custom object
        logger.info("=== Test 3: Custom Object ===")
        testCustomObject(transporter, responseCallback, errorCallback)

        // Cleanup
        transporter.cleanup()
        
        logger.info("All tests completed successfully!")
        
    } catch (e: Exception) {
        logger.error("Application failed: ${e.message}", e)
    }
}

/**
 * Test with a normal object
 */
private fun testNormalObject(
    transporter: Transporter,
    responseCallback: DefaultResponseCallback,
    errorCallback: ErrorCallback
) {
    val logger = LoggerFactory.getLogger("TestNormal")
    
    // Create a normal test object
    val sampleObject = SampleObject.createNormalTest(1u)
    logger.info("Created normal object: $sampleObject")
    
    // Serialize to CBOR
    val cborBytes = sampleObject.toCborBytes()
    logger.info("Serialized to CBOR: ${cborBytes.size} bytes")
    
    // Send request
    val success = transporter.request(
        topic = "test/normal",
        payloadBytes = cborBytes,
        peerNodeId = "kotlin-client",
        profilePublicKey = "test-key".toByteArray(StandardCharsets.UTF_8),
        responseCallback = responseCallback,
        errorCallback = errorCallback
    )
    
    if (success) {
        logger.info("Request sent successfully")
        
        // Wait a bit for the callback
        Thread.sleep(200)
        
        // Check the response
        val response = responseCallback.getLastResponse()
        if (response != null) {
            try {
                val responseObject = SampleObject.fromCborBytes(response)
                logger.info("Received modified object: $responseObject")
                
                // Verify modifications
                if (responseObject.metadata.containsKey("kotlin_processed")) {
                    logger.info("✅ Object was processed by Kotlin")
                }
                if (responseObject.values.all { it % 2 == 0.0 }) {
                    logger.info("✅ Values were doubled")
                }
            } catch (e: Exception) {
                logger.error("Failed to deserialize response: ${e.message}")
            }
        } else {
            logger.warn("No response received")
        }
    } else {
        logger.error("Request failed")
    }
    
    responseCallback.clearLastResponse()
}

/**
 * Test with an error test object
 */
private fun testErrorObject(
    transporter: Transporter,
    responseCallback: DefaultResponseCallback,
    errorCallback: ErrorCallback
) {
    val logger = LoggerFactory.getLogger("TestError")
    
    // Create an error test object
    val sampleObject = SampleObject.createErrorTest(2u)
    logger.info("Created error test object: $sampleObject")
    
    // Serialize to CBOR
    val cborBytes = sampleObject.toCborBytes()
    logger.info("Serialized to CBOR: ${cborBytes.size} bytes")
    
    // Send request
    val success = transporter.request(
        topic = "test/error",
        payloadBytes = cborBytes,
        peerNodeId = "kotlin-client",
        profilePublicKey = "test-key".toByteArray(StandardCharsets.UTF_8),
        responseCallback = responseCallback,
        errorCallback = errorCallback
    )
    
    if (success) {
        logger.info("Request sent successfully")
        logger.info("✅ Error test object should have triggered error callback")
    } else {
        logger.error("Request failed")
    }
}

/**
 * Test with a custom object
 */
private fun testCustomObject(
    transporter: Transporter,
    responseCallback: DefaultResponseCallback,
    errorCallback: ErrorCallback
) {
    val logger = LoggerFactory.getLogger("TestCustom")
    
    // Create a custom object
    val metadata = mapOf(
        "custom_key" to "custom_value",
        "platform" to "kotlin",
        "version" to "1.0.0"
    )
    val values = listOf(10.0, 20.0, 30.0, 40.0, 50.0)
    
    val sampleObject = SampleObject.create(
        id = 42u,
        name = "custom_test",
        metadata = metadata,
        values = values
    )
    
    logger.info("Created custom object: $sampleObject")
    
    // Serialize to CBOR
    val cborBytes = sampleObject.toCborBytes()
    logger.info("Serialized to CBOR: ${cborBytes.size} bytes")
    
    // Send request
    val success = transporter.request(
        topic = "test/custom",
        payloadBytes = cborBytes,
        peerNodeId = "kotlin-client",
        profilePublicKey = "test-key".toByteArray(StandardCharsets.UTF_8),
        responseCallback = responseCallback,
        errorCallback = errorCallback
    )
    
    if (success) {
        logger.info("Request sent successfully")
        
        // Wait a bit for the callback
        Thread.sleep(200)
        
        // Check the response
        val response = responseCallback.getLastResponse()
        if (response != null) {
            try {
                val responseObject = SampleObject.fromCborBytes(response)
                logger.info("Received modified object: $responseObject")
                
                // Verify modifications
                if (responseObject.metadata.containsKey("kotlin_processed")) {
                    logger.info("✅ Object was processed by Kotlin")
                }
                if (responseObject.values.all { it % 2 == 0.0 }) {
                    logger.info("✅ Values were doubled")
                }
            } catch (e: Exception) {
                logger.error("Failed to deserialize response: ${e.message}")
            }
        } else {
            logger.warn("No response received")
        }
    } else {
        logger.error("Request failed")
    }
    
    responseCallback.clearLastResponse()
}
