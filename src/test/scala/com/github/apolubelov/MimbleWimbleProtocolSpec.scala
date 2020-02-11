package com.github.apolubelov

import java.nio.charset.StandardCharsets

import org.scalatest._

import scala.util.Random

class MimbleWimbleProtocolSpec extends FunSuite {
    private val message = "Antonin Dolohov's curse".getBytes(StandardCharsets.UTF_8)

    import MimbleWimbleProtocol._


    test("Single input single output should work") {
        val amount = Math.abs(new Random().nextInt())
        //
        val offered = offer(message, List(
            commitTo(amount)
        ))
        // send to counterpart ===>
        val accepted = accept(offered.toSend, List(
            commitTo(amount)
        ))
        // send back <===
        val tx = createTransaction(message, offered, accepted) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Single input multiple output should work") {
        val total = 1000
        val amount1 = 123
        val amount2 = 321
        val amount3 = total - amount1 - amount2
        //
        val offered = offer(message, List(
            commitTo(total)
        ))
        // send to counterpart ===>
        val accepted = accept(offered.toSend, List(
            commitTo(amount1),
            commitTo(amount2),
            commitTo(amount3)
        ))
        // send back <===
        val tx = createTransaction(message, offered, accepted) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Multiple input single output should work") {
        val total = 1000
        val amount1 = 123
        val amount2 = 321
        val amount3 = total - amount1 - amount2
        //
        val offered = offer(message, List(
            commitTo(amount1),
            commitTo(amount2),
            commitTo(amount3)
        ))
        // send to counterpart ===>
        val accepted = accept(offered.toSend, List(
            commitTo(total)
        ))
        // send back <===
        val tx = createTransaction(message, offered, accepted) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Multiple input multiple output should work") {
        val offered = offer(message, List(
            commitTo(123),
            commitTo(321)
        ))
        // send to counterpart ===>
        val accepted = accept(offered.toSend, List(
            commitTo(222),
            commitTo(222)
        ))
        // send back <===
        val tx = createTransaction(message, offered, accepted) // finalize tx
        // push to block chain ===>
        assert(verifyTransaction(tx)) // public validation on block chain
    }

    test("Different amounts should not work") {
        //
        val offered = offer(message, List(
            commitTo(123)
        ))
        // send to counterpart ===>
        val accepted = accept(offered.toSend, List(
            commitTo(321)
        ))
        // send back <===
        val tx = createTransaction(message, offered, accepted) // finalize tx
        // push to block chain ===>
        assert(!verifyTransaction(tx)) // public validation on block chain
    }

    // TODO: add range proofs
    //    test("Negative amounts should not work") {
    //        //
    //        val offered = offer(message, List(
    //            commitTo(123)
    //        ))
    //        // send to counterpart ===>
    //        val accepted = accept(offered.toSend, List(
    //            commitTo(123),
    //            commitTo(321),
    //            commitTo(-321),
    //        ))
    //        // send back <===
    //        val tx = createTransaction(message, offered, accepted) // finalize tx
    //        // push to block chain ===>
    //        assert(!verifyTransaction(tx)) // public validation on block chain
    //    }
}
