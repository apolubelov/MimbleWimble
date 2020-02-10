package example

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom, Security}

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.{ECDomainParameters, ECKeyGenerationParameters, ECPrivateKeyParameters, ECPublicKeyParameters}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex

object Main extends App {
    Security.addProvider(new BouncyCastleProvider)

    import ECC._

    val message = "Hey there!"
    val msgBytes = message.getBytes(StandardCharsets.UTF_8)

    //
    // .1
    val (ir, iGr, i) = MW.commitTo(BigInteger.valueOf(100))
    val (iGk, ik) = generateKP()

    // => iGr, iGk
    // .2
    val (or, oGr, o) = MW.commitTo(BigInteger.valueOf(100))
    val (oGk, ok) = generateKP()

    // .2.1
    val oE = new BigInteger(Hash(iGk + oGk, msgBytes)) //+ oGr + iGr
    val oS = ok + or * oE

    // => oGr, oGk
    // .3
    val iE = new BigInteger(Hash(iGk + oGk, msgBytes)) //+ oGr + iGr
    val iS = ik + ir.negate() * iE

    val s = oS + iS

    val pubKey = o - i

    //        println(pubKey)
    //println()

    println(s"s: ${s.length} : ${s.toString(16)}\ne: ${iE.length} : ${iE.toString(16)}\ns: ${ir.length} : ${ir.toString(16)}")

    val isValid = SchnorrAlgo.verify(msgBytes, pubKey, (s, iE))
    println(s"Valid: $isValid")


    ////    val (pk1, sk1) = generateKP()
    ////    val (pk2, sk2) = generateKP()
    //
    //    //    val privateKey = sk1 - sk2
    ////    val publicKey = pk1 - pk2
    //
    //    val sk1 = or
    //    val sk2 = ir
    //    val publicKey = o - i
    //
    //    val rk1 = generateKP()
    //    val rk2 = generateKP()
    //
    //    val s1 = SchnorrAlgo.sign2(msgBytes, sk1, rk1, rk2)
    //    val s2 = SchnorrAlgo.sign2(msgBytes, sk2.negate(), rk2, rk1)
    //
    //    val signature = (s1._1 + s2._1, s1._2)
    //
    //    val isValid = SchnorrAlgo.verify(msgBytes, publicKey, signature)
    //
    //    val s = signature._1.toByteArray
    //    val e = signature._2.toByteArray
    //
    //    println(s"IsValid: $isValid")
    ////    println(s"s: ${s.length}, e: ${e.length}, sk: ${privateKey.length}")
}

object MW {

    import ECC._

    private val HBytes =
        Hex.decode("0450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac031d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904")

    val H: ECPoint = ECC.ECSpec.getCurve.decodePoint(HBytes)


    def commitTo(v: BigInteger): (BigInteger, ECPoint, ECPoint) = {
        val (rg, r) = generateKP()
        (r, rg, rg + H * v)
    }
}

object SchnorrAlgo {

    import ECC._

    def sign(data: Array[Byte], key: Array[Byte]): (BigInteger, BigInteger) = {
        val x = new BigInteger(key)
        val (r, k) = generateKP() // random k, r = G*k
        val e = new BigInteger(Hash(r, data))
        val s = k + x * e
        (s, e)
    }

    def sign2(data: Array[Byte], key: BigInteger, r: ECPoint, k: BigInteger): (BigInteger, BigInteger) = {
        val e = new BigInteger(Hash(r, data))
        val s = k + key * e
        (s, e)
    }

    def verify(data: Array[Byte], publicKey: Array[Byte], signature: (BigInteger, BigInteger)): Boolean = {
        val y = ECSpec.getCurve.decodePoint(publicKey)
        val (s, e) = signature
        val rv = G * s + y * e.negate()
        val ev = new BigInteger(Hash(rv, data))
        ev == e
    }
}

object ECC {
    val ECSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val G: ECPoint = ECSpec.getG
    val q: BigInteger = ECSpec.getCurve.getOrder


    def generateKP(): (ECPoint, BigInteger) = {
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
        val kp: AsymmetricCipherKeyPair = kpGen.generateKeyPair()
        (kp.getPublic.asInstanceOf[ECPublicKeyParameters].getQ, kp.getPrivate.asInstanceOf[ECPrivateKeyParameters].getD)
    }

    implicit class ECPOps(p: ECPoint) {
        def +(o: ECPoint): ECPoint = p.add(o)

        def -(o: ECPoint): ECPoint = p.subtract(o)

        def *(k: BigInteger): ECPoint = p.multiply(k)
    }

    implicit class BigIntOps(k: BigInteger) {
        def +(o: BigInteger): BigInteger = k.add(o).mod(q)

        def -(o: BigInteger): BigInteger = k.subtract(o).mod(q)

        def *(p: ECPoint): ECPoint = p.multiply(k)

        def *(p: BigInteger): BigInteger = k.multiply(p).mod(q)

        def ==(o: BigInteger): Boolean = k.compareTo(o) == 0
    }


    implicit val ECPoint2Bytes: ECPoint => Array[Byte] = _.getEncoded(false)

    implicit val BigInteger2Bytes: BigInteger => Array[Byte] = _.toByteArray

}

object Hash {

    def apply(data: Array[Byte]*): Array[Byte] = {
        val digest = MessageDigest.getInstance("SHA-256")
        data.foreach(digest.update)
        digest.digest()
    }
}
