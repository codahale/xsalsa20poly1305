# XSalsa20Poly1305

[![CircleCI](https://circleci.com/gh/codahale/xsalsa20poly1305.svg?style=svg)](https://circleci.com/gh/codahale/xsalsa20poly1305)

A pure Java library which provides symmetric and asymmetric encryption compatible with DJB's NaCl
library and its variants (e.g. libsodium). Also includes a class compatible with RbNaCl's SimpleBox
construction, which automatically manages nonces for you in a misuse-resistant fashion.

## Add to your project

```xml
<dependency>
  <groupId>com.codahale</groupId>
  <artifactId>xsalsa20poly1305</artifactId>
  <version>0.11.0</version>
</dependency>
```

*Note: module name for Java 9+ is `com.codahale.xsalsa20poly1305`.*

It depends on Bouncy Castle for Salsa20, XSalsa20, Poly1305, and X25519 implementations.

## Examples

```java
import java.nio.charset.StandardCharsets;
import com.codahale.xsalsa20poly1305.Keys;
import com.codahale.xsalsa20poly1305.SimpleBox;

class Examples {
  void asymmetricEncryption() {
    // Alice has a key pair
    final byte[] alicePrivateKey = Keys.generatePrivateKey();
    final byte[] alicePublicKey = Keys.generatePublicKey(alicePrivateKey);
    
    // Bob also has a key pair
    final byte[] bobPrivateKey = Keys.generatePrivateKey();
    final byte[] bobPublicKey = Keys.generatePublicKey(bobPrivateKey);
    
    // Bob and Alice exchange public keys. (Not pictured.)
    
    // Bob wants to send Alice a very secret message. 
    final byte[] message = "this is very secret".getBytes(StandardCharsets.UTF_8);
    
    // Bob encrypts the message using Alice's public key and his own private key
    final SimpleBox bobBox = new SimpleBox(alicePublicKey, bobPrivateKey);
    final byte[] ciphertext = bobBox.seal(message);
    
    // Bob sends Alice this ciphertext. (Not pictured.)
    
    // Alice decrypts the message using Bob's public key and her own private key.
    final SimpleBox aliceBox = new SimpleBox(bobPublicKey, alicePrivateKey);
    final byte[] plaintext = aliceBox.open(ciphertext);
    
    // Now Alice has the message!
    System.out.println(new String(plaintext, StandardCharsets.UTF_8));
  }
 
  void symmetricEncryption() {
    // There is a single secret key.
    final byte[] secretKey = Keys.generateSecretKey();  
   
    // And you want to use it to store a very secret message.
    final byte[] message = "this is very secret".getBytes(StandardCharsets.UTF_8);
   
    // So you encrypt it.
    final SimpleBox box = new SimpleBox(secretKey);
    final byte[] ciphertext = box.seal(message);
    
    // And you store it. (Not pictured.)
    
    // And then you decrypt it later.
    final byte[] plaintext = box.open(ciphertext);
    
    // Now you have the message again!
    System.out.println(new String(plaintext, StandardCharsets.UTF_8));
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

`SecretBox#nonce(byte[])` uses the BLAKE2b hash algorithm, keyed with the given key and using
randomly-generated 128-bit salt and personalization parameters. If the local `SecureRandom`
implementation is functional, the hash algorithm mixes those 256 bits of entropy along with the key
and message to produce a 192-bit nonce, which will have the same chance of collision as
`SecretBox#nonce()`. In the event that the local `SecureRandom` implementation is misconfigured,
exhausted of entropy, or otherwise compromised, the generated nonce will be unique to the given
combination of key and message, thereby preserving the security of the messages. Please note that in
this event, using `SecretBox#nonce()` to encrypt messages will be deterministic -- duplicate
messages will produce duplicate ciphertexts, and this will be observable to any attackers.

Because of the catastrophic downside risk of nonce reuse, the `SimpleBox` functions use
`SecretBox#nonce(byte[])` to generate nonces.

## Performance

Plenty fast.

```
Benchmark                 (size)  Mode  Cnt     Score     Error  Units
KaliumBenchmarks.decrypt     100  avgt    5  1514.807 ±  22.722  ns/op
KaliumBenchmarks.decrypt    1024  avgt    5  1522.446 ±  39.799  ns/op
KaliumBenchmarks.decrypt   10240  avgt    5  1523.473 ±  57.312  ns/op
KaliumBenchmarks.encrypt     100  avgt    5  1257.149 ±  37.157  ns/op
KaliumBenchmarks.encrypt    1024  avgt    5  1254.206 ±  37.659  ns/op
KaliumBenchmarks.encrypt   10240  avgt    5  1252.768 ±  19.789  ns/op
OurBenchmarks.open           100  avgt    5  1247.329 ±  29.835  ns/op
OurBenchmarks.open          1024  avgt    5  1198.329 ±  28.937  ns/op
OurBenchmarks.open         10240  avgt    5  1282.656 ± 118.296  ns/op
OurBenchmarks.seal           100  avgt    5  1120.629 ±  44.919  ns/op
OurBenchmarks.seal          1024  avgt    5  1239.287 ±  12.169  ns/op
OurBenchmarks.seal         10240  avgt    5  1112.890 ±  23.699  ns/op
OurBenchmarks.simpleOpen     100  avgt    5  1269.132 ±  10.512  ns/op
OurBenchmarks.simpleOpen    1024  avgt    5  1297.270 ±  15.052  ns/op
OurBenchmarks.simpleOpen   10240  avgt    5  1288.875 ±  21.530  ns/op
OurBenchmarks.simpleSeal     100  avgt    5  7165.066 ± 155.023  ns/op
OurBenchmarks.simpleSeal    1024  avgt    5  7062.841 ± 182.324  ns/op
OurBenchmarks.simpleSeal   10240  avgt    5  7545.090 ± 540.043  ns/op
```

## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
