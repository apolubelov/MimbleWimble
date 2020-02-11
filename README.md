
Example implementation of MimbleWimble protocol in Scala

Limitations:
* No range proofs
* No [kernel offsets](https://github.com/mimblewimble/grin/blob/master/doc/intro.md#kernel-offsets)
* [Classic Schnorr signature schema](https://en.wikipedia.org/wiki/Schnorr_signature) is known to be not secure for key aggregation [see](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures)