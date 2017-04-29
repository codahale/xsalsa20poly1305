# XSalsa20Poly1305

[![Build Status](https://secure.travis-ci.org/codahale/xsalsa20poly1305.svg)](http://travis-ci.org/codahale/xsalsa20poly1305)

A pure Java library which provides symmetric and asymmetric encryption compatible with DJB's NaCl
library and its variants (e.g. libsodium). Also includes a class compatible with RbNaCl's SimpleBox
construction, which automatically manages nonces for you in a misuse-resistant fashion.

## Add to your project

```xml
<dependency>
  <groupId>com.codahale</groupId>
  <artifactId>xsalsa20poly1305</artifactId>
  <version>0.8.0</version>
</dependency>
```

It depends on Bouncy Castle for Salsa20, XSalsa20, and Poly1305 implementations, and on Open Whisper
Systems' curve25519-java for Curve25519 operations.

## Examples

```java
import com.codahale.xsalsa20poly1305.SimpleBox;
import okio.ByteString;

class Examples {
  void asymmetricEncryption() {
    // Alice has a key pair
    final ByteString alicePrivateKey = SimpleBox.generatePrivateKey();
    final ByteString alicePublicKey = SimpleBox.generatePublicKey(alicePrivateKey);
    
    // Bob also has a key pair
    final ByteString bobPrivateKey = SimpleBox.generatePrivateKey();
    final ByteString bobPublicKey = SimpleBox.generatePublicKey(bobPrivateKey);
    
    // Bob and Alice exchange public keys. (Not pictured.)
    
    // Bob wants to send Alice a very secret message. 
    final ByteString message = ByteString.encodeUtf8("this is very secret");
    
    // Bob encrypts the message using Alice's public key and his own private key
    final SimpleBox bobBox = new SimpleBox(alicePublicKey, bobPrivateKey);
    final ByteString ciphertext = bobBox.seal(message);
    
    // Bob sends Alice this ciphertext. (Not pictured.)
    
    // Alice decrypts the message using Bob's public key and her own private key.
    final SimpleBox aliceBox = new SimpleBox(bobPublicKey, alicePrivateKey);
    final ByteString plaintext = aliceBox.open(ciphertext);
    
    // Now Alice has the message!
    System.out.println(plaintext);
  }
 
  void symmetricEncryption() {
    // There is a single secret key.
    final ByteString secretKey = SimpleBox.generateSecretKey();  
   
    // And you want to use it to store a very secret message.
    final ByteString message = ByteString.encodeUtf8("this is very secret");
   
    // So you encrypt it.
    final SimpleBox box = new SimpleBox(secretKey);
    final ByteString ciphertext = box.seal(message);
    
    // And you store it. (Not pictured.)
    
    // And then you decrypt it later.
    final ByteString plaintext = box.open(ciphertext);
    
    // Now you have the message again!
    System.out.println(plaintext);
  }
  
  // There is also SecretBox, which behaves much like SimpleBox but requires you to manage your own
  // nonces. More on that later.
}
```

## Misuse-Resistant Nonces

XSalsa20Poly1305 is composed of two cryptographic primitives: XSalsa20, a stream cipher, and
Poly1305, a message authentication code. In order to be secure, both require a _nonce_ -- a bit
string which can only be used once for any given key. If a nonce is re-used -- i.e., used to encrypt
two different messages -- this can have catastrophic consequences for the confidentiality and
integrity of the encrypted messages: an attacker may be able to recover plaintext messages and even
forge seemingly-valid messages. As a result, it is incredibly important that nonces be unique.

XSalsa20 uses 24-byte (192-bit) nonces, which makes the possibility of a secure random number
generator generating the same nonce twice essentially impossible, even over trillions of messages.
For normal operations, `SecretBox#nonce()` (which simply returns 24 bytes from `SecureRandom`)
should be safe to use. But because of the downside risk of nonce misuse, this library provides a
secondary function for generating misuse-resistant nonces: `SecretBox#nonce()`, which requires the
message the nonce will be used to encrypt.

`SecretBox#nonce(ByteString)` uses the BLAKE2b hash algorithm, keyed with the given key and using
randomly-generated 128-bit salt and personalization parameters. If the local `SecureRandom`
implementation is functional, the hash algorithm mixes those 256 bits of entropy along with the key
and message to produce a 192-bit nonce, which will have the same chance of collision as
`SecretBox#nonce()`. In the event that the local `SecureRandom` implementation is misconfigured,
exhausted of entropy, or otherwise compromised, the generated nonce will be unique to the given
combination of key and message, thereby preserving the security of the messages. Please note that in
this event, using `SecretBox#nonce()` to encrypt messages will be deterministic -- duplicate
messages will produce duplicate ciphertexts, and this will be observable to any attackers.

Because of the catastrophic downside risk of nonce reuse, the `SimpleBox` functions use
`SecretBox#nonce(ByteString)` to generate nonces.

## Performance

For small messages (i.e. ~100 bytes), it's ony a little slower than `libsodium`-based libraries like
Kalium. For larger messages (i.e., ~1KiB), Kalium is faster:

```
Benchmark                         Mode  Cnt       Score       Error  Units
KaliumBenchmarks.seal100Bytes     avgt   20    1178.388 ±    38.086  ns/op
KaliumBenchmarks.seal1K           avgt   20    3216.230 ±   138.257  ns/op
KaliumBenchmarks.seal10K          avgt   20   25385.605 ±  2886.728  ns/op
OurBenchmarks.seal100Bytes        avgt   20    1779.108 ±    93.737  ns/op
OurBenchmarks.seal1K              avgt   20   12197.366 ±  1223.081  ns/op
OurBenchmarks.seal10K             avgt   20  106457.090 ± 13920.695  ns/op
OurBenchmarks.simpleSeal100Bytes  avgt   20    7525.965 ±  1541.868  ns/op
OurBenchmarks.simpleSeal1K        avgt   20   16143.608 ±  1234.535  ns/op
OurBenchmarks.simpleSeal10K       avgt   20  105926.511 ±  1814.883  ns/op
```

(These benchmarks were run on my laptop while I was making jokes on Twitter. I would expect your
production environment to be a little different.)

## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
