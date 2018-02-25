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
  <version>0.8.1</version>
</dependency>
```

It depends on Bouncy Castle for Salsa20, XSalsa20, Poly1305, and X25519 implementations.

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

Plenty fast.

```
Benchmark                 (size)  Mode  Cnt      Score     Error  Units
KaliumBenchmarks.decrypt     100  avgt   20   1793.539 ± 124.656  ns/op
KaliumBenchmarks.decrypt    1024  avgt   20   1473.534 ±  34.491  ns/op
KaliumBenchmarks.decrypt   10240  avgt   20   1440.947 ±  27.825  ns/op
KaliumBenchmarks.encrypt     100  avgt   20   1178.445 ±  29.802  ns/op
KaliumBenchmarks.encrypt    1024  avgt   20   1168.267 ±  28.839  ns/op
KaliumBenchmarks.encrypt   10240  avgt   20   1168.010 ±  17.696  ns/op

OurBenchmarks.open           100  avgt   20   1421.482 ±  22.579  ns/op
OurBenchmarks.open          1024  avgt   20   1434.875 ±  38.469  ns/op
OurBenchmarks.open         10240  avgt   20   1384.131 ±  37.711  ns/op
OurBenchmarks.seal           100  avgt   20   1445.086 ±  26.644  ns/op
OurBenchmarks.seal          1024  avgt   20   1516.173 ±  33.377  ns/op
OurBenchmarks.seal         10240  avgt   20   1444.614 ±  33.779  ns/op

OurBenchmarks.simpleOpen     100  avgt   20   1433.761 ±  38.734  ns/op
OurBenchmarks.simpleOpen    1024  avgt   20   1434.190 ±  19.630  ns/op
OurBenchmarks.simpleOpen   10240  avgt   20   1427.694 ±  47.438  ns/op
OurBenchmarks.simpleSeal     100  avgt   20  10559.574 ± 331.472  ns/op
OurBenchmarks.simpleSeal    1024  avgt   20  10911.187 ± 251.743  ns/op
OurBenchmarks.simpleSeal   10240  avgt   20  10830.519 ± 218.606  ns/op
```

## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
