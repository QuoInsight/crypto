using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace myNameSpace {

  class myClass {

    public static AesCryptoServiceProvider getAes256Provider() {
      /*
        DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5
        [ https://stackoverflow.com/questions/33420630/replicate-oracle-aes-256-encryption-to-c-sharp ]
      */
      const string privateKey = "01234567890123456789012345678901";  // 32 bytes privateKeyBytes
      var aes = new AesCryptoServiceProvider();
      aes.BlockSize = 128;
      aes.KeySize = 256;  // = 8-bits x 32-bytes
      aes.Key = System.Text.Encoding.GetEncoding(1252).GetBytes(privateKey);
      aes.IV = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};  // 16 bytes sharedIVKeyBytes Initialization Vector: Default is all zeroes in DBMS_CRYPTO !!
      aes.Mode = CipherMode.CBC;  // Cipher Block Chaining
      aes.Padding = PaddingMode.PKCS7;  // Same as PKCS5/7. Provides padding which complies with the PKCS#5: Password-Based Cryptography Standard.
      return aes;
    }

    private static void Main(string[] args) {
      string action="DECRYPT", filePath="";
      if ( args.Length < 1 || args[0]=="/?" ) {
        Console.Error.WriteLine("Aes256 Encryption/Decryption.");
        Console.Error.WriteLine();
        Console.Error.WriteLine("crypt.exe [-e] <filepath>");  // args[0] args[1]
        Console.Error.WriteLine("  -e         encrypting the file, default is decrypting");
        Console.Error.WriteLine("  <filepath> path of file to be encrypted or decrypted");
        Console.Error.WriteLine();
        return;
      } else if ( args.Length > 1 && args[0]=="-e" ) {
        action = "ENCRYPT";
        filePath = args[1];
      } else {
        filePath = args[0];
      }

      // [ https://www.codeproject.com/Questions/562372/Theplusinputplusdataplusisplusnotplusapluscomplete ]
      FileStream reader = new FileStream(filePath, FileMode.Open, FileAccess.Read);
      FileStream writer = new FileStream(filePath+".txt", FileMode.OpenOrCreate, FileAccess.Write);
      using (var aes = getAes256Provider()) {
        using (ICryptoTransform cryptor = (action=="DECRYPT") ? aes.CreateDecryptor(aes.Key, aes.IV) : aes.CreateEncryptor(aes.Key, aes.IV)  ) {
          //Create a Crypt Stream using the encryptor/decryptor created above
          System.Security.Cryptography.CryptoStream cryptoStream
            = new System.Security.Cryptography.CryptoStream(writer, cryptor, CryptoStreamMode.Write);

          byte[] bites = new byte[1024]; //Stores 1 KB
          Int32 bitesRead = 0; //Number of Bytes read
          Int64 totalBites = 0; //Total Number of Bytes read

          //Loop through the entire file reading 1 kb at a time
          while (!(totalBites >= reader.Length)) {
            bitesRead = reader.Read(bites, 0, 1024); //Read the bytes from the input file.
            cryptoStream.Write(bites, 0, bitesRead); //Write the encrypted bytes to the output file.
            totalBites += bitesRead;
          }
          cryptoStream.Close();  cryptoStream.Dispose();
          cryptor.Dispose();
        }
      }
      //Close and release streams:
      reader.Close();  reader.Dispose();
      writer.Close();  writer.Dispose();
    }

  }
}

