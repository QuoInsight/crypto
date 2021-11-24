using System;
using System.Security.Cryptography;

namespace decryptNamespace {
  public class decryptClass {

    public static byte[] hex2bytes(string strHex) {
      if (strHex.Length % 2 != 0) {
        throw new ArgumentException(
          String.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "The binary key cannot have an odd number of digits: {0}",
            strHex
          )
        );
      }
      byte[] arrBytes = new byte[strHex.Length / 2];
      for (int idx=0; idx<arrBytes.Length; idx++) {
        string hex = strHex.Substring(idx*2, 2);
        arrBytes[idx] = byte.Parse(
          hex,
          System.Globalization.NumberStyles.HexNumber,
          System.Globalization.CultureInfo.InvariantCulture
        );
      }
      return arrBytes; 
    }

    public static string decryptDES3(string strData, string strKey) {
      string strDecrypt = strData;
      byte[] arrData = hex2bytes(strData);
      
      System.Security.Cryptography.TripleDESCryptoServiceProvider provDES3
        = new System.Security.Cryptography.TripleDESCryptoServiceProvider();
        provDES3.Key = System.Text.UTF8Encoding.UTF8.GetBytes(strKey.Substring(0,24));
        provDES3.Mode = System.Security.Cryptography.CipherMode.CBC;
        provDES3.IV = hex2bytes("0000000000000000"); // this is important !!
        provDES3.Padding = System.Security.Cryptography.PaddingMode.PKCS7; // this is OK

      System.Security.Cryptography.ICryptoTransform decryptor = provDES3.CreateDecryptor();
      byte[] arrResult = decryptor.TransformFinalBlock(arrData, 0, arrData.Length);
      provDES3.Clear();

      strDecrypt = System.Text.UTF8Encoding.UTF8.GetString(arrResult);
      return strDecrypt;
    }

    ////////////////////////////////////////////////////////////////////

    public static System.Security.Cryptography.AesCryptoServiceProvider getAes256Provider(string privateKey) {
      /*
        DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5
        [ https://stackoverflow.com/questions/33420630/replicate-oracle-aes-256-encryption-to-c-sharp ]
      */
      System.Security.Cryptography.AesCryptoServiceProvider aes
        = new System.Security.Cryptography.AesCryptoServiceProvider();
        aes.BlockSize = 128;
        aes.KeySize = 256;  // = 8-bits x 32-bytes
        aes.Key = System.Text.Encoding.GetEncoding(1252).GetBytes(privateKey);  // 32 bytes privateKeyBytes
        aes.IV = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  // 16 bytes sharedIVKeyBytes Initialization Vector: Default is all zeroes in DBMS_CRYPTO !!
        aes.Mode = CipherMode.CBC;  // Cipher Block Chaining
        aes.Padding = PaddingMode.PKCS7;  // Same as PKCS5/7. Provides padding which complies with the PKCS#5: Password-Based Cryptography Standard.
      return aes;
    }

    public static string decryptAes256(byte[] encrypted, string strKey) {
      string strDecrypt = "";
      using (var aes = getAes256Provider(strKey)) {
        using (System.Security.Cryptography.ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV)) {
          byte[] decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
          strDecrypt = System.Text.Encoding.UTF8.GetString(decrypted);
          decryptor.Dispose();
        }
      }
      return strDecrypt;
    }

  } // public class decryptClass;
}
