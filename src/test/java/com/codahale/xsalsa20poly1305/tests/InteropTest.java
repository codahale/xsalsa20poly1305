/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.xsalsa20poly1305.tests;

import static com.codahale.xsalsa20poly1305.tests.Generators.byteArrays;
import static org.quicktheories.quicktheories.QuickTheory.qt;

import com.codahale.xsalsa20poly1305.SecretBox;
import java.util.Arrays;
import java.util.Optional;
import org.junit.Test;

public class InteropTest {

  @Test
  public void fromUsToLibSodium() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final byte[] ciphertext = ourEncrypt(key, nonce, message);
          final Optional<byte[]> plaintext = theirDecrypt(key, nonce, ciphertext);
          return plaintext.map(p -> Arrays.equals(p, message)).orElse(false);
        });
  }

  @Test
  public void fromLibSodiumToUs() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final byte[] ciphertext = theirEncrypt(key, nonce, message);
          final Optional<byte[]> plaintext = ourDecrypt(key, nonce, ciphertext);
          return plaintext.map(p -> Arrays.equals(p, message)).orElse(false);
        });
  }

  private Optional<byte[]> theirDecrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
    try {
      return Optional.of(new org.abstractj.kalium.crypto.SecretBox(key).decrypt(nonce, ciphertext));
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

  private byte[] ourEncrypt(byte[] key, byte[] nonce, byte[] message) {
    return new SecretBox(key).seal(nonce, message);
  }


  private Optional<byte[]> ourDecrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
    return new SecretBox(key).open(nonce, ciphertext);
  }

  private byte[] theirEncrypt(byte[] key, byte[] nonce, byte[] message) {
    return new org.abstractj.kalium.crypto.SecretBox(key).encrypt(nonce, message);
  }
}
