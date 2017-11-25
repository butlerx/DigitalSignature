import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.util.*;

class Key {

  public static BigInteger n, d, p, q, e;

  public static void init(){
    p = loadPrime("./config/primeP.txt");
    q = loadPrime("./config/primeQ.txt");
    n = p.multiply(q);
    BigInteger temp = p.subtract(BigInteger.ONE);
    BigInteger phi = temp.multiply(q.subtract(BigInteger.ONE));
    e = BigInteger.valueOf(65537);
    while (e.compareTo(phi) >= 0 || !relativelyPrime(phi, e)) {
      p = genPrime();
      q = genPrime();
      n = p.multiply(q);
      temp = p.subtract(BigInteger.ONE);
      phi = temp.multiply(q.subtract(BigInteger.ONE));
    }
    write("./config/primeP.txt", p);
    write("./config/primeQ.txt", q);
    d = modInverse(e, phi);
  }

  private static BigInteger gcd(BigInteger a, BigInteger b) {
    if (a == BigInteger.ZERO) {
      return b;
    }
    return gcd(b.mod(a), a);
  }

  private static boolean relativelyPrime(BigInteger a, BigInteger b) {
    return gcd(a,b).equals(BigInteger.ONE);
  }

  public static BigInteger modInverse(BigInteger a, BigInteger m) {
    BigInteger mod = m;
    BigInteger temp1, temp2;
    BigInteger bi = BigInteger.ZERO;
    BigInteger bj = BigInteger.ONE;
    if (m == BigInteger.ONE)
      return BigInteger.ZERO;
    while (a.compareTo(BigInteger.ONE) == 1) {
      temp1 = a.divide(mod);
      temp2 = mod;
      mod = a.mod(mod);
      a = temp2;
      temp2 = bi;
      bi = bj.subtract(temp1.multiply(bi));
      bj = temp2;
    }
    if (bj.compareTo(BigInteger.ZERO) == -1)
      bj = bj.add(m);
    return bj;
  }

  private static String readFile (String filePath) {
    try {
      StringBuffer fileData = new StringBuffer();
      BufferedReader reader = new BufferedReader(new FileReader(filePath));
      char[] buf = new char[1024];
      int numRead=0;
      while((numRead=reader.read(buf)) != -1){
        String readData = String.valueOf(buf, 0, numRead);
        fileData.append(readData);
      }
      reader.close();
      return fileData.toString().replace("\n", "").replace("\r", "");
    } catch(IOException e) {
      return null;
    }
  }

  private static void setUp (String folder) {
    File dir = new File(folder);
    dir.mkdir();
  }

  private static BigInteger genPrime() {
    BigInteger prime = BigInteger.ZERO;
    while (prime.bitLength() != 512) {
      Random rnd = new SecureRandom();
      prime = BigInteger.probablePrime(512, rnd);
    }
    return prime;
  }

  private static BigInteger loadPrime (String filePath) {
    try {
      setUp("./config");
      Path file = Paths.get(filePath);
      Files.createFile(file);
      BigInteger prime = genPrime();
      return prime;
    } catch(IOException e) {
      String primeString = readFile(filePath);
      BigInteger prime = new BigInteger(primeString, 16);
      return prime;
    }
  }

  public static void write (String fileName, BigInteger key) {
    try {
      List<String> lines = Arrays.asList(key.toString(16));
      Path file = Paths.get(fileName);
      Files.write(file, lines, Charset.forName("UTF-8"));
    } catch(IOException e) {
      System.out.println(e.getMessage());
    }
  }
}

public class Sign {
  public static void main (final String[] args) throws Exception {
    Key.init();
    Key.write("./modulus", Key.n);
    sign(args[0]);
  }

  public static void sign (String file) {
    try {
      Path path = Paths.get(file);
      byte[] message = Files.readAllBytes(path);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(message);
      byte [] digest = md.digest();
      message = decrypt(digest);
      System.out.println(file + ".signed");
      Path sPath = Paths.get(file + ".signed");
      List<String> lines = Arrays.asList(javax.xml.bind.DatatypeConverter.printHexBinary(message));
      Files.write(sPath, lines, Charset.forName("UTF-8"));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static byte[] decrypt (byte[] message) {
    BigInteger bi = new BigInteger(message);
    modPow(Key.d, bi);
    byte[] signed = bi.toByteArray();
    return signed;
  }

  private static byte[] encrypt (byte[] message) {
    BigInteger bi = new BigInteger(message);
    modPow(Key.e, bi);
    byte[] signed = bi.toByteArray();
    return signed;
  }

  private static BigInteger modPow (BigInteger d, BigInteger message) {
    BigInteger p, q, inverse, message1, message2, h;
    p = d.mod(Key.p.subtract(BigInteger.ONE));
    q = d.mod(Key.q.subtract(BigInteger.ONE));
    inverse = Key.modInverse(Key.q, Key.p);
    message1 = message.modPow(p, Key.p);
    message2 = message.modPow(q, Key.q);
    h = inverse.multiply(message1.subtract(message2)).mod(Key.p);
    message = message2.add(h.multiply(Key.q));
    return message;
  }
}
