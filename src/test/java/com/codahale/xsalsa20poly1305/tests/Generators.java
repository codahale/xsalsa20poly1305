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

import java.util.Arrays;
import org.quicktheories.quicktheories.core.Source;

interface Generators {

  static Source<byte[]> byteArrays(int minLength, int maxLength) {
    return Source.of((prng, step) -> {
      final byte[] bytes = new byte[prng.nextInt(minLength, maxLength)];
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) prng.nextInt(0, 255);
      }
      return bytes;
    }).describedAs(Arrays::toString);
  }
}
