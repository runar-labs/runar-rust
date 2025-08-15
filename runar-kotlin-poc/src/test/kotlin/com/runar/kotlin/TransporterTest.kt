package com.runar.kotlin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TransporterTest {

    @Test
    fun `test transporter initialization`() {
        val transporter = RustTransporter()
        
        assertTrue(transporter.init())
        assertTrue(transporter.cleanup())
    }

    @Test
    fun `test normal object request`() {
        val transporter = RustTransporter()
        val responseCallback = DefaultResponseCallback()
        val errorCallback = DefaultErrorCallback()
        
        assertTrue(transporter.init())
        
        // Create and send a normal object
        val sampleObject = SampleObject.createNormalTest(1u)
        val cborBytes = sampleObject.toCborBytes()
        
        val success = transporter.request(
            topic = "test/normal",
            payloadBytes = cborBytes,
            peerNodeId = "test-client",
            profilePublicKey = "test-key".toByteArray(),
            responseCallback = responseCallback,
            errorCallback = errorCallback
        )
        
        assertTrue(success)
        
        // Wait for processing
        Thread.sleep(300)
        
        // Check response
        val response = responseCallback.getLastResponse()
        assertNotNull(response)
        
        // Verify the response can be deserialized
        val responseObject = SampleObject.fromCborBytes(response)
        assertTrue(responseObject.metadata.containsKey("kotlin_processed"))
        assertTrue(responseObject.values.all { it % 2 == 0.0 })
        
        transporter.cleanup()
    }

    @Test
    fun `test error object request`() {
        val transporter = RustTransporter()
        val responseCallback = DefaultResponseCallback()
        val errorCallback = DefaultErrorCallback()
        
        assertTrue(transporter.init())
        
        // Create and send an error test object
        val sampleObject = SampleObject.createErrorTest(2u)
        val cborBytes = sampleObject.toCborBytes()
        
        val success = transporter.request(
            topic = "test/error",
            payloadBytes = cborBytes,
            peerNodeId = "test-client",
            profilePublicKey = "test-key".toByteArray(),
            responseCallback = responseCallback,
            errorCallback = errorCallback
        )
        
        assertTrue(success)
        
        // Wait for processing
        Thread.sleep(300)
        
        // For error test objects, we expect no response
        val response = responseCallback.getLastResponse()
        // Response might be null for error test objects
        
        transporter.cleanup()
    }

    @Test
    fun `test custom object request`() {
        val transporter = RustTransporter()
        val responseCallback = DefaultResponseCallback()
        val errorCallback = DefaultErrorCallback()
        
        assertTrue(transporter.init())
        
        // Create a custom object
        val metadata = mapOf(
            "custom_key" to "custom_value",
            "test" to "true"
        )
        val values = listOf(5.0, 10.0, 15.0)
        
        val sampleObject = SampleObject.create(
            id = 123u,
            name = "custom_test",
            metadata = metadata,
            values = values
        )
        
        val cborBytes = sampleObject.toCborBytes()
        
        val success = transporter.request(
            topic = "test/custom",
            payloadBytes = cborBytes,
            peerNodeId = "test-client",
            profilePublicKey = "test-key".toByteArray(),
            responseCallback = responseCallback,
            errorCallback = errorCallback
        )
        
        assertTrue(success)
        
        // Wait for processing
        Thread.sleep(300)
        
        // Check response
        val response = responseCallback.getLastResponse()
        assertNotNull(response)
        
        // Verify the response can be deserialized
        val responseObject = SampleObject.fromCborBytes(response)
        assertEquals(123u, responseObject.id)
        assertEquals("custom_test", responseObject.name)
        assertTrue(responseObject.metadata.containsKey("kotlin_processed"))
        assertTrue(responseObject.values.all { it % 2 == 0.0 })
        
        transporter.cleanup()
    }

    @Test
    fun `test request without initialization`() {
        val transporter = RustTransporter()
        val responseCallback = DefaultResponseCallback()
        val errorCallback = DefaultErrorCallback()
        
        // Try to send request without initializing
        val sampleObject = SampleObject.createNormalTest(1u)
        val cborBytes = sampleObject.toCborBytes()
        
        val success = transporter.request(
            topic = "test/error",
            payloadBytes = cborBytes,
            peerNodeId = "test-client",
            profilePublicKey = "test-key".toByteArray(),
            responseCallback = responseCallback,
            errorCallback = errorCallback
        )
        
        assertFalse(success)
    }
}
