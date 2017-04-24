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
import static com.codahale.xsalsa20poly1305.tests.Generators.keyPairs;
import static org.quicktheories.quicktheories.QuickTheory.qt;

import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.Arrays;
import org.junit.Test;

public class SimpleBoxTest {

  @Test
  public void roundTrip() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check((key, message) -> {
          final SimpleBox box = new SimpleBox(key);
          return box.open(box.seal(message))
                    .map(v -> Arrays.equals(v, message))
                    .orElse(false);
        });
  }

  @Test
  public void pkRoundTrip() throws Exception {
    qt().forAll(keyPairs(), keyPairs(), byteArrays(1, 4096))
        .check((pairA, pairB, message) -> {
          final SimpleBox boxA = new SimpleBox(pairB.publicKey, pairA.privateKey);
          final SimpleBox boxB = new SimpleBox(pairA.publicKey, pairB.privateKey);
          return boxB.open(boxA.seal(message))
                     .map(p -> Arrays.equals(p, message))
                     .orElse(false);
        });
  }

  @Test
  public void shortMessage() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 24))
        .check((key, message) -> !new SimpleBox(key).open(message).isPresent());
  }
}