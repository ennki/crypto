using System;
using System.Security.Cryptography;
using System.Text;
using Cryptography;
using Xunit;

namespace Cryptography.Tests
{
    public class CryptoTests
    {
        [Fact]
        public void EveryTimeDifferentTest()
        {
            var encrypted1 = Crypto.Encrypt("test", "pwd");
            var encrypted2 = Crypto.Encrypt("test", "pwd");

            Assert.NotEqual(encrypted1, encrypted2);
        }

        [Fact]
        public void EncryptDecryptTest()
        {
            var encrypted = Crypto.Encrypt("test", "pwd");
            var decrypted = Crypto.Decrypt(encrypted, "pwd");

            Assert.Equal("test", decrypted);
        }

        [Fact]
        public void HashTest()
        {
            var hash1 = Crypto.Hash("test");
            var hash2 = Crypto.Hash("test");

            Assert.Equal(hash1, hash2);
        }
    }
}
