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

import com.codahale.xsalsa20poly1305.InvalidCiphertextException;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.Arrays;
import org.junit.Test;

public class SimpleBoxTest {

  @Test
  public void roundTrip() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check((key, message) -> {
          final SimpleBox box = new SimpleBox(key);
          final byte[] ciphertext = box.seal(message);
          try {
            final byte[] plaintext = box.open(ciphertext);
            return Arrays.equals(plaintext, message);
          } catch (InvalidCiphertextException e) {
            return false;
          }
        });
  }

  @Test
  public void shortMessage() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 24))
        .check((key, message) -> {
          try {
            new SimpleBox(key).open(message);
            return false;
          } catch (InvalidCiphertextException e) {
            return true;
          }
        });
  }
}