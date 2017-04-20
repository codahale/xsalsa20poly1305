package com.codahale;

import com.codahale.xsalsa20poly1305.SecretBox;
import com.codahale.xsalsa20poly1305.SimpleBox;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class OurBenchmarks {

  private static final byte[] key = new byte[32];
  private static final SecretBox box = new SecretBox(key);
  private static final SimpleBox simpleBox = new SimpleBox(key);
  private static final byte[] nonce = new byte[24];
  private static final byte[] msg100 = new byte[100];
  private static final byte[] msg1K = new byte[1024];
  private static final byte[] msg10K = new byte[10 * 1024];

  @Benchmark
  public byte[] seal100Bytes() {
    return box.seal(nonce, msg100);
  }

  @Benchmark
  public byte[] seal1K() {
    return box.seal(nonce, msg1K);
  }

  @Benchmark
  public byte[] seal10K() {
    return box.seal(nonce, msg10K);
  }

  @Benchmark
  public byte[] simpleSeal100Bytes() {
    return simpleBox.seal(msg100);
  }

  @Benchmark
  public byte[] simpleSeal1K() {
    return simpleBox.seal(msg1K);
  }

  @Benchmark
  public byte[] simpleSeal10K() {
    return simpleBox.seal(msg10K);
  }
}
