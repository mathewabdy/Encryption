using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;
using Security;

namespace StringEncryptionTetst
{
    public class KeyGeneratorTest
    {
        [SetUp]
        public void SetUp()
        {
        }

        [Test]
        public void Test128BitKeyReturned()
        {
            string key = KeyGenerator.Generate128BitKey();
            Assert.NotNull(key);
        }

        [Test]
        public void Test256BitKeyReturned()
        {
            string key = KeyGenerator.Generate256BitKey();
            Assert.NotNull(key);
        }
    }
}
