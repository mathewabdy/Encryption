using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;
using Security;

namespace StringEncryptionTetst
{
    public class StringEncryptionTest
    {
        private byte[] _key;
        private string _password;
        private StringEncryption _encryption;
        [SetUp]
        public void SetUp()
        {
            _password = "12345678";
            string generatedKey = KeyGenerator.Generate128BitKey();
            _key = Convert.FromBase64String(generatedKey); 
        }

        [Test]
        public void TestStringEncryption()
        {
            _encryption = new StringEncryption(new AesCryptoServiceProvider());
            byte[] encrypted = _encryption.EncryptStringToBytes(_password, _key);
            Assert.NotNull(encrypted);
        }

        [Test]
        public void TestStringDecryption()
        {
            _encryption = new StringEncryption(new AesCryptoServiceProvider());
            byte[] encrypted = _encryption.EncryptStringToBytes(_password, _key);

            string unencrypted = _encryption.DecryptStringFromBytes(encrypted, _key);
            Assert.AreEqual(unencrypted, _password);
        }

        [Test]
        [ExpectedException(typeof (CryptographicException))]
        public void TestStringDecryptionDoesNotDecryptForInvalidPassword()
        {
            _encryption = new StringEncryption(new AesCryptoServiceProvider());
            var decryption = new StringEncryption(new AesCryptoServiceProvider());
            byte[] encrypted = _encryption.EncryptStringToBytes(_password, _key);
            Encoding enc = new UnicodeEncoding();
            byte[] badPassBytes = enc.GetBytes("2dor39tp");

            decryption.DecryptStringFromBytes(encrypted, badPassBytes);
        }

        [Test]
        public void TestStringToStringEncryption()
        {
            _encryption = new StringEncryption(new AesCryptoServiceProvider());
            string encrypted = _encryption.EncryptStringToString(_password, _key);
            Assert.AreNotEqual(encrypted, _password);
            Assert.NotNull(encrypted);
        }

        [Test]
        public void TestStringToStringDecryption()
        {
            _encryption = new StringEncryption(new AesCryptoServiceProvider());
            string encrypted = _encryption.EncryptStringToString(_password, _key);

            string unencrypted = _encryption.DecryptStringFromString(encrypted, _key);
            Assert.AreNotEqual(encrypted, _password);
            Assert.AreNotEqual(encrypted, unencrypted);
            Assert.AreEqual(unencrypted, _password);
        }

    }
}
