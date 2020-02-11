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

    val message = "Hey there!"
    val msgBytes = message.getBytes(StandardCharsets.UTF_8)

    val offer =
        MW.offerMoney(
            message,
            List(
                MW.commitTo(1),
                MW.commitTo(2),
                MW.commitTo(3),
                MW.commitTo(4)
            )
        )

    // send to counterpart ===>

    val accept =
        MW.acceptMoney(
            offer.external,
            List(
                MW.commitTo(5),
                MW.commitTo(3),
                MW.commitTo(2)
            )
        )

    // send back <===
    val tx = MW.createTransaction(message, offer, accept)

    // push to block chain ===>

    // public validation on block chain
    val isValid = MW.verifyTransaction(tx)
    println(s"Valid: $isValid")

}

object MW {

    import Secp256k1._

    type Signature = (BigInteger, BigInteger)
    type KeyPair = (BigInteger, ECPoint)
    type Commitment = ECPoint

    private val HBytes =
        Hex.decode("0450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac031d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904")

    val H: ECPoint = Secp256k1.ECSpec.getCurve.decodePoint(HBytes)

    def commitTo(v: Long): PedersenCommitment = {
        val (r, rG) = generateKP()
        PedersenCommitment(
            value = v,
            blindingFactor = r,
            commitmentToBlindingFactor = rG,
            theCommitment = rG + H * BigInteger.valueOf(v)
        )
    }

    def offerMoney(message: String, inputs: List[PedersenCommitment]): InternalMoneyOffer = {
        val (signKey, commitmentToSignature) = generateKP()
        InternalMoneyOffer(
            MoneyOffer(
                value = inputs.map(_.value).sum,
                message = message.getBytes(StandardCharsets.UTF_8),
                commitmentToSignature = commitmentToSignature
            ),
            inputs, signKey
        )
    }

    def acceptMoney(offer: MoneyOffer, outputs: List[PedersenCommitment]): MoneyAccept = {
        val (signKey, commitmentToSignature) = generateKP()
        val commonCommitmentToSignature = offer.commitmentToSignature + commitmentToSignature
        val outputKeys = outputs.sumOf(_.blindingFactor)
        val signature =
            SchnorrAlgo.sign(
                data = offer.message,
                key = outputKeys.negate(), // must negate as pub key will be (inputs * G - outputs * G)
                r = commonCommitmentToSignature,
                k = signKey
            )
        MoneyAccept(
            outputs = outputs.map(_.theCommitment),
            commitmentToSignature = commitmentToSignature,
            receiverSignature = signature
        )
    }

    def createTransaction(message: String, offer: InternalMoneyOffer, accept: MoneyAccept): Transaction = {
        val commonCommitmentToSignature = offer.external.commitmentToSignature + accept.commitmentToSignature
        val outputKeys = offer.inputs.sumOf(_.blindingFactor)
        val senderSignature =
            SchnorrAlgo.sign(
                data = offer.external.message,
                key = outputKeys, //
                r = commonCommitmentToSignature,
                k = offer.signKey
            )
        val signature = (senderSignature._1 + accept.receiverSignature._1, senderSignature._2)
        Transaction(
            offer.external.message,
            inputs = offer.inputs.map(_.theCommitment),
            outputs = accept.outputs,
            signature = signature
        )
    }


    def verifyTransaction(tx: Transaction): Boolean = {
        val input = sum(tx.inputs)
        val output = sum(tx.outputs)
        val excess = input - output
        SchnorrAlgo.verify(tx.message, excess, tx.signature)
    }

    implicit class SignatureOps(s: Signature) {
        def +(o: Signature): Signature = (s._1 + o._1, s._2 + o._2)
    }

    implicit class KeyPairOps(kp: KeyPair) {
        def +(o: KeyPair): KeyPair = (kp._1 + o._1, kp._2 + o._2)
    }

    implicit class SumBigIntegersOf[T](values: Iterable[T]) {
        def sumOf(f: T => BigInteger): BigInteger = {
            values.foldRight(BigInteger.valueOf(0)) { case (c, v) => f(c) + v }
        }
    }

}

case class InternalMoneyOffer(
  external: MoneyOffer,
  //toRemember:
  inputs: List[PedersenCommitment],
  signKey: BigInteger
)

case class MoneyOffer(
  value: Long,
  message: Array[Byte],
  commitmentToSignature: ECPoint // from sender
)

case class MoneyAccept(
  outputs: List[ECPoint],
  commitmentToSignature: ECPoint, // from receiver
  receiverSignature: (BigInteger, BigInteger)
)

case class Transaction(
  message: Array[Byte],
  inputs: List[ECPoint],
  outputs: List[ECPoint],
  signature: (BigInteger, BigInteger)
)

case class PedersenCommitment(
  value: Long,
  blindingFactor: BigInteger,
  commitmentToBlindingFactor: ECPoint,
  theCommitment: ECPoint
)

object SchnorrAlgo {

    import Secp256k1._

    def sign(data: Array[Byte], key: BigInteger): (BigInteger, BigInteger) = {
        val (k, r) = generateKP() // random k, r = G*k
        sign(data, key, r, k)
    }

    def sign(data: Array[Byte], key: BigInteger, r: ECPoint, k: BigInteger): (BigInteger, BigInteger) = {
        val e = new BigInteger(Hash(r, data))
        val s = k + key * e
        (s, e)
    }

    def verify(data: Array[Byte], publicKey: ECPoint, signature: (BigInteger, BigInteger)): Boolean = {
        val y = ECSpec.getCurve.decodePoint(publicKey)
        val (s, e) = signature
        val rv = G * s + y * e.negate()
        val ev = new BigInteger(Hash(rv, data))
        ev == e
    }
}

object Secp256k1 {
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

    def generateKP(): (BigInteger, ECPoint) = {
        val kp: AsymmetricCipherKeyPair = keyPairGenerator.generateKeyPair()
        (
          kp.getPrivate.asInstanceOf[ECPrivateKeyParameters].getD,
          kp.getPublic.asInstanceOf[ECPublicKeyParameters].getQ
        )
    }

    def sum(points: List[ECPoint]): ECPoint = points.foldRight(ECSpec.getCurve.getInfinity) { case (v, c) => c + v }

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
