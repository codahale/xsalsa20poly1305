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
import static org.quicktheories.quicktheories.generators.SourceDSL.integers;

import com.codahale.xsalsa20poly1305.InvalidCiphertextException;
import com.codahale.xsalsa20poly1305.SecretBox;
import java.util.Arrays;
import org.junit.Test;

public class SecretBoxTest {

  @Test
  public void roundTrip() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096))
        .check((key, nonce, message) -> {
          final SecretBox box = new SecretBox(key);
          final byte[] ciphertext = box.seal(nonce, message);
          try {
            final byte[] plaintext = box.open(nonce, ciphertext);
            return Arrays.equals(message, plaintext);
          } catch (InvalidCiphertextException e) {
            return false;
          }
        });
  }

  @Test
  public void badKey() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(32, 32))
        .assuming((keyA, nonce, message, keyB) -> !Arrays.equals(keyA, keyB))
        .check((keyA, nonce, message, keyB) -> {
          final byte[] ciphertext = new SecretBox(keyA).seal(nonce, message);
          try {
            new SecretBox(keyB).open(nonce, ciphertext);
            return false;
          } catch (InvalidCiphertextException e) {
            return true;
          }
        });
  }

  @Test
  public void badNonce() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), byteArrays(24, 24))
        .check((key, nonceA, message, nonceB) -> {
          final SecretBox box = new SecretBox(key);
          final byte[] ciphertext = box.seal(nonceA, message);
          try {
            box.open(nonceB, ciphertext);
            return false;
          } catch (InvalidCiphertextException e) {
            return true;
          }
        });
  }

  @Test
  public void badCiphertext() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(24, 24), byteArrays(1, 4096), integers().allPositive())
        .check((key, nonce, message, v) -> {
          final SecretBox box = new SecretBox(key);
          final byte[] ciphertext = box.seal(nonce, message);
          try {
            // flip a single random bit of plaintext
            int mask = (1 << (v%8));
            if (mask == 0) {
              mask = 1;
            }
            ciphertext[v % ciphertext.length] ^= mask;
            box.open(nonce, ciphertext);
            return false;
          } catch (InvalidCiphertextException e) {
            return true;
          }
        });
  }
}