package com.example.util

// Kotlin source to exercise .kt package parsing and field resolution.
object Cache {
    val data = HashMap<String, Any>()

    fun put(key: String, value: Any) {
        data[key] = value
    }
}
