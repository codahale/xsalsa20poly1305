package com.codahale.xsalsa20poly1305;

import static org.bouncycastle.util.Pack.intToLittleEndian;
import static org.bouncycastle.util.Pack.littleEndianToInt;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.engines.Salsa20Engine;

/**
 * An implementation of the HSalsa20 hash based on the Bouncy Castle Salsa20 core.
 */
interface HSalsa20 {

  byte[] SIGMA = "expand 32-byte k".getBytes(StandardCharsets.US_ASCII);

  static void hsalsa20(byte[] out, byte[] in, byte[] k) {
    final int[] x = new int[16];

    x[0] = littleEndianToInt(HSalsa20.SIGMA, 0);
    x[1] = littleEndianToInt(k, 0);
    x[2] = littleEndianToInt(k, 4);
    x[3] = littleEndianToInt(k, 8);
    x[4] = littleEndianToInt(k, 12);
    x[5] = littleEndianToInt(HSalsa20.SIGMA, 4);
    x[6] = littleEndianToInt(in, 0);
    x[7] = littleEndianToInt(in, 4);
    x[8] = littleEndianToInt(in, 8);
    x[9] = littleEndianToInt(in, 12);
    x[10] = littleEndianToInt(HSalsa20.SIGMA, 8);
    x[11] = littleEndianToInt(k, 16);
    x[12] = littleEndianToInt(k, 20);
    x[13] = littleEndianToInt(k, 24);
    x[14] = littleEndianToInt(k, 28);
    x[15] = littleEndianToInt(HSalsa20.SIGMA, 12);

    Salsa20Engine.salsaCore(20, x, x);

    x[0] -= littleEndianToInt(HSalsa20.SIGMA, 0);
    x[5] -= littleEndianToInt(HSalsa20.SIGMA, 4);
    x[10] -= littleEndianToInt(HSalsa20.SIGMA, 8);
    x[15] -= littleEndianToInt(HSalsa20.SIGMA, 12);
    x[6] -= littleEndianToInt(in, 0);
    x[7] -= littleEndianToInt(in, 4);
    x[8] -= littleEndianToInt(in, 8);
    x[9] -= littleEndianToInt(in, 12);

    intToLittleEndian(x[0], out, 0);
    intToLittleEndian(x[5], out, 4);
    intToLittleEndian(x[10], out, 8);
    intToLittleEndian(x[15], out, 12);
    intToLittleEndian(x[6], out, 16);
    intToLittleEndian(x[7], out, 20);
    intToLittleEndian(x[8], out, 24);
    intToLittleEndian(x[9], out, 28);
  }
}
