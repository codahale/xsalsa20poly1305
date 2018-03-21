# Change Log

## v0.10.1: 2018-03-20

* Minor optimizations for HSalsa20 transform.

## v0.10.0: 2018-03-14

* Extracted key generation methods to new `Keys` class.

## v0.9.1: 2018-03-08

* Added `sharedSecret` methods to `SecretBox` and `SimpleBox`.

## v0.9.0: 2018-02-25

* Upgraded Bouncy Castle.
* Upgraded okio.
* Dropped `curve25519-java` dependency.

## v0.8.1: 2017-05-15

* Upgraded Bouncy Castle.
* Upgraded okio.

## v0.8.0: 2017-04-28

* Moved API to `ByteString`s.

## v0.7.0: 2017-04-24

* Added support for NaCl-compatible Curve25519 asymmetric encryption.
* Added key generation methods.
* Renamed both nonce generation methods to `nonce`.

## v0.6.0: 2017-04-20

* Folded `Nonces` functionality into `SecretBox`.

## v0.5.0: 2017-04-20

* Initial Java release. A Clojure library with the same Maven coordinates exists in Clojars.