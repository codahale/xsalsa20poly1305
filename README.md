# XSalsa20Poly1305

[![Build Status](https://secure.travis-ci.org/codahale/xsalsa20poly1305.svg)](http://travis-ci.org/codahale/xsalsa20poly1305)

A pure Java implementation of XSalsa20Poly1305 authenticated encryption, compatible with DJB's NaCl
`secretbox` construction. Includes a set of functions compatible with RbNaCl's SimpleBox
construction, which automatically manages nonces for you in a misuse-resistant fashion.

## Add to your project

```xml
<dependency>
  <groupId>com.codahale</groupId>
  <artifactId>xsalsa20poly1305</artifactId>
  <version>0.5.0</version>
</dependency>
```

## Use the thing

```java
import com.codahale.xsalsa20poly1305.SecretBox;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.Optional;

class Example {
  // if you don't want to manage nonces yourself
  void simpleRoundTrip() {
    final byte[] key = "ayellowsubmarineayellowsubmarine".getBytes();
    final SimpleBox box = new SimpleBox(key);
        
    final byte[] message = "hello, it's me".getBytes();
    final byte[] ciphertext = box.seal(key, message);
    final Optional<byte[]> plaintext = box.open(key, ciphertext);
  
    if (plaintext.isPresent()) {
      System.out.println(new String(plaintext.get()));
    } else {
      System.err.println("Unable to decrypt data"); 
    }
  }
    
  // if you do want to manage nonces
  void complexRoundTrip() {
    final byte[] key = "ayellowsubmarineayellowsubmarine".getBytes();
    final SecretBox box = new SecretBox(key);
        
    final byte[] message = "hello, it's me".getBytes();
    final byte[] nonce = box.misuseResistantNonce(message);
    final byte[] ciphertext = box.seal(key, nonce, message);
    final Optional<byte[]> plaintext = box.open(key, nonce, ciphertext);
    
    if (plaintext.isPresent()) {
      System.out.println(new String(plaintext.get()));
    } else {
      System.err.println("Unable to decrypt data"); 
    }
  }
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
For normal operations, `SecretBox.randomNonce()` (which simply returns 24 bytes from `SecureRandom`)
should be safe to use. But because of the downside risk of nonce misuse, this library provides a
secondary function for generating misuse-resistant nonces: `SecretBox.misuseResistantNonce()`, which
requires the key and message the nonce will be used to encrypt.

`SecretBox.misuseResistantNonce()` uses the BLAKE2b hash algorithm, keyed with the given key and
using randomly-generated 128-bit salt and personalization parameters. If the local `SecureRandom`
implementation is functional, the hash algorithm mixes those 256 bits of entropy along with the key
and message to produce a 192-bit nonce, which will have the same chance of collision as
`SecretBox.randomNonce()`. In the event that the local `SecureRandom` implementation is
misconfigured, exhausted of entropy, or otherwise compromised, the generated nonce will be unique to
the given combination of key and message, thereby preserving the security of the messages. Please
note that in this event, using `SecretBox.misuseResistantNonce()` to encrypt messages will be
deterministic -- duplicate messages will produce duplicate ciphertexts, and this will be observable
to any attackers.

Because of the catastrophic downside risk of nonce reuse, the `SimpleBox` functions use
`SecretBox.misuseResistantNonce()` to generate nonces.

## Performance

For small messages (i.e. ~100 bytes), it's about as fast as `libsodium`-based libraries like Kalium,
but depends only on Bouncy Castle, which is pure Java. For larger messages (i.e., ~1KiB), Kalium is
faster:

```
Benchmark                      Mode  Cnt      Score      Error  Units
KaliumBenchmarks.seal100Bytes  avgt  200   1035.706 ±   15.781  ns/op
KaliumBenchmarks.seal1K        avgt  200   2783.802 ±   18.837  ns/op
KaliumBenchmarks.seal10K       avgt  200  21238.330 ±  174.044  ns/op
OurBenchmarks.seal100Bytes     avgt  200   1458.108 ±   13.039  ns/op
OurBenchmarks.seal1K           avgt  200   8999.346 ±   81.191  ns/op
OurBenchmarks.seal10K          avgt  200  83373.701 ± 1184.940  ns/op
```
## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
