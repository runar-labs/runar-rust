package com.runar.kotlin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SampleObjectTest {

    @Test
    fun `test create normal object`() {
        val metadata = mapOf("test" to "value")
        val values = listOf(1.0, 2.0, 3.0)
        
        val obj = SampleObject.create(42u, "test", metadata, values)
        
        assertEquals(42u, obj.id)
        assertEquals("test", obj.name)
        assertEquals(metadata, obj.metadata)
        assertEquals(values, obj.values)
        assertTrue(obj.timestamp > 0)
    }

    @Test
    fun `test create error test object`() {
        val obj = SampleObject.createErrorTest(999u)
        
        assertEquals(999u, obj.id)
        assertEquals("ERROR", obj.name)
        assertTrue(obj.isErrorTest())
    }

    @Test
    fun `test create normal test object`() {
        val obj = SampleObject.createNormalTest(888u)
        
        assertEquals(888u, obj.id)
        assertEquals("NORMAL", obj.name)
        assertFalse(obj.isErrorTest())
    }

    @Test
    fun `test error test detection`() {
        val normalObj = SampleObject.create(1u, "normal", mapOf(), listOf())
        val errorObj = SampleObject.create(2u, "ERROR", mapOf(), listOf())
        
        assertFalse(normalObj.isErrorTest())
        assertTrue(errorObj.isErrorTest())
    }

    @Test
    fun `test CBOR serialization and deserialization`() {
        val metadata = mapOf(
            "key1" to "value1",
            "key2" to "value2"
        )
        val values = listOf(1.5, 2.5, 3.5)
        
        val original = SampleObject.create(42u, "serialization_test", metadata, values)
        
        // Serialize to CBOR
        val cborBytes = original.toCborBytes()
        assertTrue(cborBytes.isNotEmpty())
        
        // Deserialize from CBOR
        val deserialized = SampleObject.fromCborBytes(cborBytes)
        
        // Verify all fields match
        assertEquals(original.id, deserialized.id)
        assertEquals(original.name, deserialized.name)
        assertEquals(original.timestamp, deserialized.timestamp)
        assertEquals(original.metadata, deserialized.metadata)
        assertEquals(original.values, deserialized.values)
    }

    @Test
    fun `test object modification`() {
        val metadata = mapOf("original" to "value")
        val values = listOf(1.0, 2.0)
        
        val original = SampleObject.create(1u, "test", metadata, values)
        val modified = original.copy(
            metadata = original.metadata + mapOf(
                "processed" to "true",
                "timestamp" to "1234567890"
            ),
            values = original.values.map { it * 2.0 }
        )
        
        // Check that original is unchanged
        assertEquals(1, original.metadata.size)
        assertEquals(1.0, original.values[0])
        assertEquals(2.0, original.values[1])
        
        // Check that modified has new data
        assertEquals(3, modified.metadata.size)
        assertTrue(modified.metadata.containsKey("processed"))
        assertTrue(modified.metadata.containsKey("timestamp"))
        assertEquals(2.0, modified.values[0])
        assertEquals(4.0, modified.values[1])
    }
}
