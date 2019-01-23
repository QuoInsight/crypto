using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace myNameSpace {

  public class myMainClass {

    public static AesCryptoServiceProvider getAes256Provider() {
      /*
        DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5
        [ https://stackoverflow.com/questions/33420630/replicate-oracle-aes-256-encryption-to-c-sharp ]
      */
      const string privateKey = "01234567890123456789012345678901";
      var aes = new AesCryptoServiceProvider();
      aes.BlockSize = 128;
      aes.KeySize = 256;
      aes.Key = System.Text.Encoding.GetEncoding(1252).GetBytes(privateKey);  // 32 bytes privateKeyBytes
      aes.IV = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  // 16 bytes sharedIVKeyBytes Initialization Vector: Default is all zeroes in DBMS_CRYPTO !!
      aes.Mode = CipherMode.CBC;  // Cipher Block Chaining
      aes.Padding = PaddingMode.PKCS7;  // Same as PKCS5/7. Provides padding which complies with the PKCS#5: Password-Based Cryptography Standard.
      return aes;
    }

    public static string EncryptUsingAes(AesCryptoServiceProvider aes, byte[] inputBytes) {
      byte[] outputBytes = new byte[inputBytes.Length];
      using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV)) {
        outputBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
        encryptor.Dispose();
      }
      string encryptedText = System.Text.Encoding.GetEncoding(1252).GetString(outputBytes);
      // hexstring == BitConverter.ToString(outputBytes).Replace("-", "");
      return encryptedText;
    }

    public static string DecryptUsingAes(AesCryptoServiceProvider aes, byte[] inputBytes) {
      byte[] outputBytes = new byte[inputBytes.Length];
      using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV)) {
        outputBytes = decryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
        decryptor.Dispose();
      }
      // Convert byte array to string
      return Encoding.GetEncoding(1252).GetString(outputBytes);
    }

    public static void Main(string[] args) {
      // var utf8 = new System.Text.UTF8Encoding(); // System.Text.UTF8Encoding ==> BOM:No vs. System.Text.Encoding.UTF8 ==> BOM:Yes

      string inputText = "Test";
      Console.WriteLine("inputText: '{0}'", inputText);

      //try {
        Console.WriteLine("********************EncryptUsingAes******************");
        byte[] inputBytes = System.Text.Encoding.GetEncoding(1252).GetBytes(inputText);
        Console.WriteLine("inputBytes: {0}", inputBytes.Length);

        using (var aes = getAes256Provider()) {
          string encryptedText = string.Empty;
          encryptedText = EncryptUsingAes(aes, inputBytes);
          Console.WriteLine("Encrypted text [length={0}]: '{1}'", encryptedText.Length, encryptedText);
          Console.WriteLine(System.Convert.ToBase64String(System.Text.Encoding.GetEncoding(1252).GetBytes(encryptedText)));
          Console.WriteLine();

          Console.WriteLine("********************DecryptUsingAes******************");
          byte[] encryptedBytes = System.Text.Encoding.GetEncoding(1252).GetBytes(encryptedText);
          Console.WriteLine("encryptedBytes: {0}", encryptedBytes.Length);

          string decryptedText = string.Empty;
          decryptedText = DecryptUsingAes(aes, encryptedBytes);
          Console.WriteLine("Decrypted text is: '{0}'", decryptedText);
          Console.WriteLine();
        }
      //} catch (Exception e) {
      //  Console.WriteLine("Exception: {0}", e.Message);
      //}
    }

  }
}

