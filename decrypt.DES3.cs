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
        provDES3.Mode = CipherMode.CBC;
        provDES3.IV = hex2bytes("0000000000000000"); // this is important !!
        provDES3.Padding = PaddingMode.PKCS7; // this is OK

      System.Security.Cryptography.ICryptoTransform decryptor = provDES3.CreateDecryptor();
      byte[] arrResult = decryptor.TransformFinalBlock(arrData, 0, arrData.Length);
      provDES3.Clear();

      strDecrypt = System.Text.UTF8Encoding.UTF8.GetString(arrResult);
      return strDecrypt;
    }

  } // public class decryptClass;
}
