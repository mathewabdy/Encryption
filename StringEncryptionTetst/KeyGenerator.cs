using System;
using System.Security.Cryptography;

namespace Security
{
    public static class KeyGenerator
    {
        public static string Generate128BitKey()
        {
            return GenerateBytes(16);
        }

        public static string Generate256BitKey()
        {
            return GenerateBytes(32);
        }

        private static string GenerateBytes(int length)
        {
            var bytes = new byte[length]; 
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
