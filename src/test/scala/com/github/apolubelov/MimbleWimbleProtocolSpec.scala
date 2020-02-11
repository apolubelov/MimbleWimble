package com.github.apolubelov

import java.nio.charset.StandardCharsets

import org.scalatest._

import scala.util.Random

class MimbleWimbleProtocolSpec extends FunSuite {
    private val message = "Antonin Dolohov's curse".getBytes(StandardCharsets.UTF_8)

    import MimbleWimbleProtocol._


    test("Single input single output should work") {
        val amount = Math.abs(new Random().nextLong())
        //
        val offer = offerMoney(message, List(
            commitTo(amount)
        ))
        // send to counterpart ===>
        val accept = acceptMoney(offer.external, List(
            commitTo(amount)
        ))
        // send back <===
        val tx = createTransaction(message, offer, accept) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Single input multiple output should work") {
        val total = 1000
        val amount1 = 123
        val amount2 = 321
        val amount3 = total - amount1 - amount2
        //
        val offer = offerMoney(message, List(
            commitTo(total)
        ))
        // send to counterpart ===>
        val accept = acceptMoney(offer.external, List(
            commitTo(amount1),
            commitTo(amount2),
            commitTo(amount3)
        ))
        // send back <===
        val tx = createTransaction(message, offer, accept) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Multiple input single output should work") {
        val total = 1000
        val amount1 = 123
        val amount2 = 321
        val amount3 = total - amount1 - amount2
        //
        val offer = offerMoney(message, List(
            commitTo(amount1),
            commitTo(amount2),
            commitTo(amount3)
        ))
        // send to counterpart ===>
        val accept = acceptMoney(offer.external, List(
            commitTo(total)
        ))
        // send back <===
        val tx = createTransaction(message, offer, accept) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Multiple input multiple output should work") {
        val offer = offerMoney(message, List(
            commitTo(123),
            commitTo(321)
        ))
        // send to counterpart ===>
        val accept = acceptMoney(offer.external, List(
            commitTo(222),
            commitTo(222)
        ))
        // send back <===
        val tx = createTransaction(message, offer, accept) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

}
