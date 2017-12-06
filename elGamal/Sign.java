/*
The MIT License (MIT)

Copyright (c) 2017 Cian Butler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

class Key {

  private BigInteger x, y, p, g;

  Key() throws Exception {
    try {
      FS fs = new FS();
      p = fs.read("./modulus.txt");
      g = fs.read("./generator.txt");
      int keyLen = p.bitLength() - 1;
      SecureRandom sec = new SecureRandom();
      // Private key x where 1 < x < p-1
      x = new BigInteger(keyLen, sec);
      // Public key y = g^x (mod p)
      y = g.modPow(x, p);
    } catch (FileNotFoundException e) {
      throw e;
    }
  }

  public BigInteger publicKey() {
    return y;
  }

  public BigInteger privateKey() {
    return x;
  }

  public BigInteger modulus() {
    return p;
  }

  public BigInteger generator() {
    return g;
  }
}

public class Sign {
  private static BigInteger gcd(BigInteger a, BigInteger b) {
    if (a == BigInteger.ZERO) return b;
    return gcd(b.mod(a), a);
  }

  public static BigInteger modInverse(BigInteger a, BigInteger m) {
    BigInteger mod = m;
    BigInteger temp1, temp2;
    BigInteger bi = BigInteger.ZERO;
    BigInteger bj = BigInteger.ONE;
    if (m == BigInteger.ONE) return BigInteger.ZERO;
    while (a.compareTo(BigInteger.ONE) == 1) {
      temp1 = a.divide(mod);
      temp2 = mod;
      mod = a.mod(mod);
      a = temp2;
      temp2 = bi;
      bi = bj.subtract(temp1.multiply(bi));
      bj = temp2;
    }
    if (bj.compareTo(BigInteger.ZERO) == -1) bj = bj.add(m);
    return bj;
  }

  private static BigInteger r, s;

  private static void genRS(Key key, byte[] msg) {
    s = BigInteger.ZERO;
    BigInteger p = key.modulus();
    BigInteger temp = p.subtract(BigInteger.ONE);
    int keyLen = p.bitLength() - 1;

    while (s.equals(BigInteger.ZERO)) {
      BigInteger k = BigInteger.ZERO;
      while (!k.equals(BigInteger.ONE)) {
        SecureRandom sec_r = new SecureRandom();
        k = new BigInteger(keyLen, sec_r);
        k = gcd(k, temp);
      }
      r = key.generator().modPow(k, p);
      BigInteger hash = new BigInteger(msg);
      s = hash.subtract(key.privateKey().multiply(r));
      try {
        s = s.multiply(modInverse(k, temp));
        s = s.mod(temp);
      } catch (ArithmeticException e) {
        s = BigInteger.ZERO;
      }
    }
  }

  public static boolean inBounds(Key key) {
    return ((r.compareTo(BigInteger.ZERO) == 1)
        & (r.compareTo(key.modulus()) == -1)
        & (s.compareTo(BigInteger.ZERO) == 1)
        & (s.compareTo(key.modulus().subtract(BigInteger.ONE)) == -1));
  }

  public static boolean verify(Key key, byte[] digest) {
    BigInteger left = key.generator().modPow(new BigInteger(digest), key.modulus());
    BigInteger bi = key.publicKey().modPow(r, key.modulus());
    BigInteger bj = r.modPow(s, key.modulus());
    BigInteger tmp = bi.multiply(bj);
    BigInteger right = tmp.mod(key.modulus());
    return (left.equals(right));
  }

  public static void main(final String[] args) {
    try {
      Key key = new Key();
      Path path = Paths.get(args[0]);
      byte[] message = Files.readAllBytes(path);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(message);
      byte[] digest = md.digest();
      genRS(key, digest);
      if (inBounds(key) & verify(key, digest)) {
        prettyPrint("Private Key", key.privateKey().toString(16));
        prettyPrint("Public Key", key.publicKey().toString(16));
        prettyPrint("r", r.toString(16));
        prettyPrint("s", s.toString(16));
        System.exit(0);
      } else {
        System.out.println("R and S failed verification");
        System.exit(1);
      }
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }

  private static void prettyPrint(String var, String hex) {
    StringBuilder builder = new StringBuilder(hex.length() + 1 * (hex.length() / 8) + 1);
    String prefix = "";
    int block = 0;
    for (int i = 0; i < hex.length(); i += 8) {
      if (block % 8 == 0) {
        builder.append("\n");
      } else {
        builder.append(prefix);
      }
      prefix = " ";
      builder.append(hex.substring(i, Math.min(i + 8, hex.length())));
      block++;
    }
    var = " " + var + " ";
    String padding = String.format("%0" + ((71 - var.length()) / 2) + "d", 0).replace("0", "=");
    System.out.println(padding + var + padding + "\n" + builder.toString() + "\n");
  }
}

class FS {

  FS() {}

  public BigInteger read(String filePath) throws Exception {
    try {
      StringBuffer fileData = new StringBuffer();
      BufferedReader reader = new BufferedReader(new FileReader(filePath));
      char[] buf = new char[1024];
      int numRead = 0;
      while ((numRead = reader.read(buf)) != -1) {
        String readData = String.valueOf(buf, 0, numRead);
        fileData.append(readData);
      }
      reader.close();
      String file =
          fileData.toString().replaceAll("\\s", "").replaceAll("\\n", "").replaceAll("\\r", "");
      return new BigInteger(file, 16);
    } catch (IOException e) {
      throw e;
    }
  }
}
