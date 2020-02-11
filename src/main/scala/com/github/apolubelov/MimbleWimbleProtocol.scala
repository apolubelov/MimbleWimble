package com.github.apolubelov

import java.math.BigInteger

import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex


object MimbleWimbleProtocol {

    import Secp256k1._

    type Key = BigInteger
    type Signature = (BigInteger, BigInteger)
    type KeyPair = (BigInteger, ECPoint)
    type Commitment = ECPoint

    private val HBytes =
        Hex.decode("0450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac031d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904")

    val H: ECPoint = Secp256k1.ECSpec.getCurve.decodePoint(HBytes)

    def commitTo(v: Long): PedersenCommitment = {
        val (r, rG) = generateKeyPair()
        PedersenCommitment(
            value = v,
            blindingFactor = r,
            commitmentToBlindingFactor = rG,
            theCommitment = rG + H * BigInteger.valueOf(v)
        )
    }

    def offerMoney(message: Array[Byte], inputs: List[PedersenCommitment]): InternalMoneyOffer = {
        val (signKey, commitmentToSign) = generateKeyPair()
        InternalMoneyOffer(
            MoneyOffer(
                value = inputs.map(_.value).sum,
                message = message,
                commitmentToSign = commitmentToSign
            ),
            inputs, signKey
        )
    }

    def acceptMoney(offer: MoneyOffer, outputs: List[PedersenCommitment]): MoneyAccept = {
        val (signKey, commitmentToSignature) = generateKeyPair()
        val commonCommitmentToSignature = offer.commitmentToSign + commitmentToSignature
        val outputKeys = outputs.sumOf(_.blindingFactor)
        val signature =
            SchnorrSignature.sign(
                data = offer.message,
                key = outputKeys.negate(), // must negate to match pub key (inputs * G - outputs * G)
                r = commonCommitmentToSignature,
                k = signKey
            )
        MoneyAccept(
            outputs = outputs.map(_.theCommitment),
            commitmentToSign = commitmentToSignature,
            receiverSignature = signature
        )
    }

    def createTransaction(message: Array[Byte], offer: InternalMoneyOffer, accept: MoneyAccept): Transaction = {
        val commonCommitmentToSignature = offer.external.commitmentToSign + accept.commitmentToSign
        val outputKeys = offer.inputs.sumOf(_.blindingFactor)
        val senderSignature =
            SchnorrSignature.sign(
                data = offer.external.message,
                key = outputKeys, //
                r = commonCommitmentToSignature,
                k = offer.signKey
            )
        val signature = senderSignature + accept.receiverSignature
        Transaction(
            offer.external.message,
            inputs = offer.inputs.map(_.theCommitment),
            outputs = accept.outputs,
            signature = signature
        )
    }

    def verifyTransaction(tx: Transaction): Boolean = {
        val input = sumOf(tx.inputs)
        val output = sumOf(tx.outputs)
        val excess = input - output
        SchnorrSignature.verify(tx.message, excess, tx.signature)
    }

    implicit class SignatureOps(s: Signature) {
        def +(o: Signature): Signature = (s._1 + o._1, s._2)
    }

    implicit class KeyPairOps(kp: KeyPair) {
        def +(o: KeyPair): KeyPair = (kp._1 + o._1, kp._2 + o._2)
    }

    implicit class SumBigIntegersOf[T](values: Iterable[T]) {
        def sumOf(f: T => BigInteger): BigInteger = {
            values.foldRight(BigInteger.valueOf(0)) { case (c, v) => f(c) + v }
        }
    }

    case class InternalMoneyOffer(
      external: MoneyOffer,
      //toRemember:
      inputs: List[PedersenCommitment],
      signKey: Key
    )

    case class MoneyOffer(
      value: Long,
      message: Array[Byte],
      commitmentToSign: Commitment // from sender
    )

    case class MoneyAccept(
      outputs: List[Commitment],
      commitmentToSign: Commitment, // from receiver
      receiverSignature: Signature
    )

    case class Transaction(
      message: Array[Byte],
      inputs: List[Commitment],
      outputs: List[Commitment],
      signature: Signature
    )

    case class PedersenCommitment(
      value: Long,
      blindingFactor: Key,
      commitmentToBlindingFactor: Commitment,
      theCommitment: Commitment
    )
}

