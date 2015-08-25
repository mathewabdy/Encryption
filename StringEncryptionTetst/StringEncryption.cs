using System;
using System.IO;
using System.Security.Cryptography;

namespace Security
{
    public class StringEncryption
    {
        private readonly Aes _aes;

        public StringEncryption(Aes aes)
        {
            _aes = aes;
        }

        /// <summary>
        /// Will encrypt the given string using the provided key
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <returns>Encrypted ByteArray</returns>
        public byte[] EncryptStringToBytes(string plainText, byte[] key)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length < 16)
                throw new ArgumentNullException("key");
            byte[] encrypted;
           
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = _aes.IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        /// <summary>
        /// Will decryt the string given the provided key
        /// </summary>
        /// <param name="encryptedBytes"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public string DecryptStringFromBytes(byte[] encryptedBytes, byte[] key)
        {
            if (encryptedBytes == null || encryptedBytes.Length <= 0)
                throw new ArgumentNullException("encryptedBytes");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            
            string plaintext;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = _aes.IV;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        /// <summary>
        /// Will encrypt the given string using the provided key
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <returns>Encrypted ByteArray</returns>
        public string EncryptStringToString(string plainText, byte[] key)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            byte[] encrypted;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = _aes.IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Will decryt the string given the provided key
        /// </summary>
        /// <param name="encryptedString"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public string DecryptStringFromString(string encryptedString, byte[] key)
        {
            if (encryptedString == null || encryptedString.Length <= 0)
                throw new ArgumentNullException("encryptedString");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");

            string plaintext;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = _aes.IV;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedString)))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

    }
}
