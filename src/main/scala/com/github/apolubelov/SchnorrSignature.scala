package com.github.apolubelov

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint

object SchnorrSignature {

    import Secp256k1._

    def sign(data: Array[Byte], key: BigInteger): (BigInteger, BigInteger) = {
        val (k, r) = generateKeyPair() // random k, r = G*k
        sign(data, key, r, k)
    }

    def sign(data: Array[Byte], key: BigInteger, r: ECPoint, k: BigInteger): (BigInteger, BigInteger) = {
        val e = Hash256(r.asBytes, data)
        val s = k + key * e
        (s, e)
    }

    def verify(data: Array[Byte], publicKey: ECPoint, signature: (BigInteger, BigInteger)): Boolean = {
        val y = publicKey
        val (s, e) = signature
        val rv = G * s + y * e.negate()
        val ev = Hash256(rv.asBytes, data)
        ev == e
    }
}