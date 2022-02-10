using System;

namespace IdeaCipher
{
  /**
   * Creates an instance of the IDEA processor, initialized with a 16-byte binary key.
   * https://github.com/LexBritvin/IdeaCipher
   * @param key
   *  A 16-byte binary key.
   * @param encrypt
   *  true to encrypt, false to decrypt.
   * ## modified by CKL036

      byte[] HexStringToByteArray(string hexString) {
        byte[] byteArr = new byte[(int)(hexString.Length/2)];
        for (int i=0; i<byteArr.Length; i++) {
          byteArr[i] = (byte)Convert.ToInt32(hexString.Substring(i*2,2), 16);
        }
        return byteArr;
      }

      string ByteArrayToHexString(byte[] ba) {
        System.Text.StringBuilder hex = new System.Text.StringBuilder(ba.Length * 2);
        foreach (byte b in ba) hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
      }

      bool encrypt = true; // true to encrypt, false to decrypt.
      //string charKey = "0123456789ABCDEF0123456789ABCDEF";
      //byte[] charKey = new byte[] {
      //  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
      //  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
      //};
      byte[] charKey = HexStringToByteArray("0123456789ABCDEF0123456789ABCDEF");

      string strData = "abc123  "; // block of 8 data bytes
      byte[] data = Encoding.ASCII.GetBytes(strData);

      IdeaCipher.IDEA idea = new IdeaCipher.IDEA(charKey, encrypt);
      idea.crypt(data, 0);
      Response.Write( ByteArrayToHexString(data) + "<br>" );

  //Response.End();

      encrypt = false;
      idea = new IdeaCipher.IDEA(charKey, encrypt);
      idea.crypt(data, 0);
      strData = Encoding.ASCII.GetString(data, 0, data.Length);
      Response.Write("[" + strData + "]<br>");

*/
  public class IDEA
  {
    // Number of rounds.
    internal static int rounds = 8;
    // Internal encryption sub-keys.
    internal int[] subKey;

    public IDEA(byte[] key, bool encrypt) {
      // Expands a 16-byte user key to the internal encryption sub-keys.
      int[] tempSubKey = expandUserKey(key);
      if (encrypt) {
        subKey = tempSubKey;
      } else {
        subKey = invertSubKey(tempSubKey);
      }
    }

    public IDEA(String charKey, bool encrypt)
     : this(generateUserKeyFromCharKey(charKey), encrypt)
    {
      for (int i=0; i<charKey.Length; i++) {
        System.Web.HttpContext.Current.Response.Write(((int)charKey[i]).ToString() + ", ");
      }
      System.Web.HttpContext.Current.Response.Write("<br><br>");
    }

    /**
     * Encrypts or decrypts a block of 8 data bytes.
     *
     * @param data
     *  Buffer containing the 8 data bytes to be encrypted/decrypted.
     */
    public void crypt(byte[] data) {
      crypt(data, 0);
    }

    /**
     * Encrypts or decrypts a block of 8 data bytes.
     *
     * @param data
     *  Data buffer containing the bytes to be encrypted/decrypted.
     * @param dataPos
     *  Start position of the 8 bytes within the buffer.
     */
    public void crypt(byte[] data, int dataPos) {

      // ## below added by CKL036
      if (data.Length < dataPos+8) {
        byte[] tmpData = new byte[dataPos+8];
        for (int i=0; i<data.Length; i++) {
          tmpData[i] = data[i];
        }
        for (int i=data.Length; i<tmpData.Length; i++) {
          tmpData[i] = 32; // append/pad with some space by default !!
        }
        data = tmpData;
      }

      int x0 = ((data[dataPos + 0] & 0xFF) << 8) | (data[dataPos + 1] & 0xFF);
      int x1 = ((data[dataPos + 2] & 0xFF) << 8) | (data[dataPos + 3] & 0xFF);
      int x2 = ((data[dataPos + 4] & 0xFF) << 8) | (data[dataPos + 5] & 0xFF);
      int x3 = ((data[dataPos + 6] & 0xFF) << 8) | (data[dataPos + 7] & 0xFF);
      //
      int p = 0;
      for (int round = 0; round < rounds; round++)
      {
        int y0 = mul(x0, subKey[p++]);
        int y1 = add(x1, subKey[p++]);
        int y2 = add(x2, subKey[p++]);
        int y3 = mul(x3, subKey[p++]);
        //
        int t0 = mul(y0 ^ y2, subKey[p++]);
        int t1 = add(y1 ^ y3, t0);
        int t2 = mul(t1, subKey[p++]);
        int t3 = add(t0, t2);
        //
        x0 = y0 ^ t2;
        x1 = y2 ^ t2;
        x2 = y1 ^ t3;
        x3 = y3 ^ t3;
      }
      //
      int r0 = mul(x0, subKey[p++]);
      int r1 = add(x2, subKey[p++]);
      int r2 = add(x1, subKey[p++]);
      int r3 = mul(x3, subKey[p++]);
      //
      data[dataPos + 0] = (byte)(r0 >> 8);
      data[dataPos + 1] = (byte)r0;
      data[dataPos + 2] = (byte)(r1 >> 8);
      data[dataPos + 3] = (byte)r1;
      data[dataPos + 4] = (byte)(r2 >> 8);
      data[dataPos + 5] = (byte)r2;
      data[dataPos + 6] = (byte)(r3 >> 8);
      data[dataPos + 7] = (byte)r3;
    }

    // Expands a 16-byte user key to the internal encryption sub-keys.
    private static int[] expandUserKey(byte[] userKey) {
      if (userKey.Length != 16) {
        throw new ArgumentException("Key length must be 128 bit", "key");
      }
      int[] key = new int[rounds * 6 + 4];  // int[52]
      for (int i = 0; i < userKey.Length / 2; i++)  { // [0..7]
        key[i] = ((userKey[2*i] & 0xFF) << 8) | (userKey[2*i + 1] & 0xFF);
      }
      for (int i = userKey.Length / 2; i < key.Length; i++) { // [8..51]
        key[i] = ((key[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9) | (key[(i + 2) % 8 < 2 ? i - 14 : i - 6] >> 7)) & 0xFFFF;
      }
      /*
        for (int i=0; i<userKey.Length; i++) {
          System.Web.HttpContext.Current.Response.Write(userKey[i].ToString() + ", ");
        }
        // 1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239,
        System.Web.HttpContext.Current.Response.Write("<br><br>");
        
        //key = new int []{
        //  291, 17767, 35243, 52719, 291, 17767, 35243, 52719,
        //  53011, 22427, 56834, 18058, 53011, 22427, 56834, 18058,
        //  14268, 1165, 5534, 9903, 14268, 1165, 5534, 9903,
        //  6699, 15437, 24175, 30729, 6699, 15437, 24175, 30729,
        //  39612, 57072, 4660, 22136, 39612, 57072, 4660, 22136,
        //  57380, 26796, 61749, 31165, 57380, 26796, 61749, 31165,
        //  23010, 27379, 31680, 18641
        //};
        for (int i=0; i<key.Length; i++) {
          System.Web.HttpContext.Current.Response.Write(key[i].ToString() + ", ");
        }
        System.Web.HttpContext.Current.Response.Write("<br><br>");
        //System.Web.HttpContext.Current.Response.End();
      */
      return key;
    }

    // Inverts decryption/encrytion sub-keys to encrytion/decryption sub-keys.
    private static int[] invertSubKey(int[] key) {
      int[] invKey = new int[key.Length];
      int p = 0;
      int i = rounds * 6;
      invKey[i + 0] = mulInv(key[p++]);
      invKey[i + 1] = addInv(key[p++]);
      invKey[i + 2] = addInv(key[p++]);
      invKey[i + 3] = mulInv(key[p++]);
      for (int r = rounds - 1; r >= 0; r--) {
        i = r * 6;
        int m = r > 0 ? 2 : 1;
        int n = r > 0 ? 1 : 2;
        invKey[i + 4] = key[p++];
        invKey[i + 5] = key[p++];
        invKey[i + 0] = mulInv(key[p++]);
        invKey[i + m] = addInv(key[p++]);
        invKey[i + n] = addInv(key[p++]);
        invKey[i + 3] = mulInv(key[p++]);
      }
      return invKey;
    }

    // Addition in the additive group.
    // The arguments and the result are within the range 0 .. 0xFFFF.
    private static int add(int a, int b) {
      return (a + b) & 0xFFFF;
    }

    // Multiplication in the multiplicative group.
    // The arguments and the result are within the range 0 .. 0xFFFF.
    private static int mul(int a, int b) {
      long r = (long)a * b;
      if (r != 0) {
        return (int)(r % 0x10001) & 0xFFFF;
      } else {
        return (1 - a - b) & 0xFFFF;
      }
    }

    // Additive Inverse.
    // The argument and the result are within the range 0 .. 0xFFFF.
    private static int addInv(int x) {
      return (0x10000 - x) & 0xFFFF;
    }

    // Multiplicative inverse.
    // The argument and the result are within the range 0 .. 0xFFFF.
    // The following condition is met for all values of x: mul(x, mulInv(x)) == 1
    private static int mulInv(int x) {
      if (x <= 1) {
        return x;
      }
      int y = 0x10001;
      int t0 = 1;
      int t1 = 0;
      while (true) {
        t1 += y / x * t0;
        y %= x;
        if (y == 1) {
          return 0x10001 - t1;
        }
        t0 += x / y * t1;
        x %= y;
        if (x == 1) {
          return t0;
        }
      }
    }
    // Generates a 16-byte binary user key from a character string key.
    private static byte[] generateUserKeyFromCharKey(String charKey) {
      int nofChar = 0x7E - 0x21 + 1;  // Number of different valid characters
      int[] a = new int[8];
      for (int p = 0; p < charKey.Length; p++) {
        int c = charKey[p];
        for (int i = a.Length - 1; i >= 0; i--) {
          c += a[i] * nofChar;
          a[i] = c & 0xFFFF;
          c >>= 16;
        }
      }
      byte[] key = new byte[16];
      for (int i = 0; i < 8; i++) {
        key[i * 2] = (byte)(a[i] >> 8);
        key[i * 2 + 1] = (byte)a[i];
      }
      return key;
    }
  }
}
