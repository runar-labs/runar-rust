package com.runar.kotlin

/**
 * Response callback interface for successful requests
 * This matches the Rust ResponseCallback function signature
 */
interface ResponseCallback {
    fun onResponse(payloadBytes: ByteArray)
}

/**
 * Error callback interface for failed requests
 * This matches the Rust ErrorCallback function signature
 */
interface ErrorCallback {
    fun onError(errorCode: UInt, errorMessage: String)
}

/**
 * Default implementation of ResponseCallback that logs and stores the response
 */
class DefaultResponseCallback : ResponseCallback {
    private val logger = org.slf4j.LoggerFactory.getLogger(DefaultResponseCallback::class.java)
    private var lastResponse: ByteArray? = null

    override fun onResponse(payloadBytes: ByteArray) {
        logger.info("Received response: ${payloadBytes.size} bytes")
        lastResponse = payloadBytes
        
        try {
            // Try to deserialize the response
            val sampleObject = SampleObject.fromCborBytes(payloadBytes)
            logger.info("Deserialized response object: $sampleObject")
        } catch (e: Exception) {
            logger.error("Failed to deserialize response: ${e.message}")
        }
    }

    fun getLastResponse(): ByteArray? = lastResponse
    fun clearLastResponse() { lastResponse = null }
}

/**
 * Default implementation of ErrorCallback that logs errors
 */
class DefaultErrorCallback : ErrorCallback {
    private val logger = org.slf4j.LoggerFactory.getLogger(DefaultErrorCallback::class.java)

    override fun onError(errorCode: UInt, errorMessage: String) {
        val errorCodeEnum = ErrorCode.fromCode(errorCode)
        logger.error("FFI Error [${errorCodeEnum.name}]: $errorMessage")
    }
}
