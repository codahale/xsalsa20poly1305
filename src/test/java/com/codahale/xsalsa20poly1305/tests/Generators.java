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
import java.util.function.Function;
import okio.ByteString;
import org.quicktheories.core.Gen;
import org.quicktheories.impl.Constraint;

public interface Generators {

  static Gen<byte[]> byteArrays(int minLength, int maxLength) {
    final Gen<byte[]> gen =
        prng -> {
          final byte[] bytes = new byte[(int) prng.next(Constraint.between(minLength, maxLength))];
          for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) prng.next(Constraint.between(0, 255));
          }
          return bytes;
        };
    return gen.describedAs(Arrays::toString);
  }

  static Gen<ByteString> byteStrings(int minLength, int maxLength) {
    return byteArrays(minLength, maxLength).map((Function<byte[], ByteString>) ByteString::of);
  }

  static Gen<ByteString> privateKeys() {
    return byteArrays(32, 32).map(Generators::clamp);
  }

  static ByteString clamp(byte[] privateKey) {
    privateKey[0] &= (byte) 248;
    privateKey[31] &= (byte) 127;
    privateKey[31] |= (byte) 64;
    return ByteString.of(privateKey);
  }
}
