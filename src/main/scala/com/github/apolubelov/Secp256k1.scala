package com.github.apolubelov

import java.math.BigInteger
import java.security.{SecureRandom, Security}

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters, ECPrivateKeyParameters, ECPublicKeyParameters}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint

object Secp256k1 {
    Security.addProvider(new BouncyCastleProvider)

    val ECSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val G: ECPoint = ECSpec.getG
    val q: BigInteger = ECSpec.getCurve.getOrder

    private val keyPairGenerator = createGenerator()

    private def createGenerator(): ECKeyPairGenerator = {
        val kpGen = new ECKeyPairGenerator()
        kpGen.init(
            new ECKeyGenerationParameters(
                new ECDomainParameters(
                    ECSpec.getCurve,
                    ECSpec.getG,
                    ECSpec.getN,
                    ECSpec.getH
                ),
                new SecureRandom()
            )
        )
        kpGen
    }

    def generateKeyPair(): (BigInteger, ECPoint) = {
        val kp: AsymmetricCipherKeyPair = keyPairGenerator.generateKeyPair()
        (
          kp.getPrivate.asInstanceOf[ECPrivateKeyParameters].getD,
          kp.getPublic.asInstanceOf[ECPublicKeyParameters].getQ
        )
    }

    def sumOf(points: List[ECPoint]): ECPoint = points.foldRight(ECSpec.getCurve.getInfinity) { case (v, c) => c + v }

    implicit class ECPOps(p: ECPoint) {
        def +(o: ECPoint): ECPoint = p.add(o)

        def -(o: ECPoint): ECPoint = p.subtract(o)

        def *(k: BigInteger): ECPoint = p.multiply(k)

        def asBytes: Array[Byte] = p.getEncoded(false)
    }

    implicit class BigIntOps(k: BigInteger) {
        def +(o: BigInteger): BigInteger = k.add(o).mod(q)

        def -(o: BigInteger): BigInteger = k.subtract(o).mod(q)

        def *(p: ECPoint): ECPoint = p.multiply(k)

        def *(p: BigInteger): BigInteger = k.multiply(p).mod(q)

        def ==(o: BigInteger): Boolean = k.compareTo(o) == 0
    }

}