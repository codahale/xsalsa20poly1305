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

import com.codahale.xsalsa20poly1305.Nonces;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.Test;

public class NoncesTest {

  @Test
  public void randomNonce() throws Exception {
    final List<byte[]> nonces = IntStream.range(0, 1000)
                                         .mapToObj(i -> Nonces.random())
                                         .collect(Collectors.toList());
    qt().forAll(integers().between(1, 1000), integers().between(1, 1000))
        .assuming((x, y) -> !Objects.equals(x, y))
        .check((x, y) -> !Arrays.equals(nonces.get(x-1), nonces.get(y-1)));
    qt().forAll(integers().all())
        .check(i -> Nonces.random().length == 24);
  }

  @Test
  public void misuseResistantNonce() throws Exception {
    qt().forAll(byteArrays(32, 32), byteArrays(1, 4096))
        .check((key, message) -> Nonces.misuseResistant(key, message).length == 24);
  }
}