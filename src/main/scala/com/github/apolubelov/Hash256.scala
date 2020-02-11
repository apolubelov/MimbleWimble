package com.github.apolubelov

import java.math.BigInteger
import java.security.MessageDigest

object Hash256 {
    private val name = "SHA-256"

    def apply(data: Array[Byte]*): BigInteger = {
        val digest = MessageDigest.getInstance(name)
        data.foreach(digest.update)
        val bytes = digest.digest()
        new BigInteger(bytes)
    }
}