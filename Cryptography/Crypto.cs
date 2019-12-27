using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    // Primitives: AES-GCM, SHA512
    // https://docs.microsoft.com/en-us/dotnet/core/whats-new/dotnet-core-3-0#cryptography-ciphers
    // Salt is generated on each encryption and added to password before key derivation
    // PBKDF2 number of iterations for key derivation: 10000-12000
    // Package format: PBKDF2 iterations (2 bytes) + salt (16 bytes) + tag (16 bytes) + nonce (12 bytes) + cipher text (rest)
    public static class Crypto
    {
        private static Encoding UTF8 = new UTF8Encoding(false, true);

        public static string Encrypt(string data, string password)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            var dataToEncrypt = UTF8.GetBytes(data);
            var packageArray = new byte[46 + dataToEncrypt.Length];
            var package = packageArray.AsSpan();
            var iterations = package.Slice(0, 2);
            var salt = package.Slice(2, 16);
            var tag = package.Slice(18, 16);
            var nonce = package.Slice(34, 12);
            var ciphertext = package.Slice(46, dataToEncrypt.Length);
            RandomNumberGenerator.Fill(salt);
            RandomNumberGenerator.Fill(iterations);
            var number = 10000 + BitConverter.ToUInt16(iterations) % 2000;
            Array.Copy(BitConverter.GetBytes(number), packageArray, 2);
            using var key = new Rfc2898DeriveBytes(password, salt.ToArray(), BitConverter.ToInt16(iterations));
            using var aesGcm = new AesGcm(key.GetBytes(16));
            RandomNumberGenerator.Fill(nonce);
            aesGcm.Encrypt(nonce, dataToEncrypt, ciphertext, tag, Array.Empty<byte>());
            return Convert.ToBase64String(package);
        }

        public static string Decrypt(string data, string password)
        {
            if (string.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            var package = Convert.FromBase64String(data);
            var iterations = package[0..2];
            var salt = package[2..18];
            var tag = package[18..34];
            var nonce = package[34..46];
            var ciphertext = package[46..^0];
            using var key = new Rfc2898DeriveBytes(password, salt, BitConverter.ToInt16(iterations));
            using var aesGcm = new AesGcm(key.GetBytes(16));
            var decryptedData = new byte[ciphertext.Length];
            aesGcm.Decrypt(nonce, ciphertext, tag, decryptedData, Array.Empty<byte>());
            return UTF8.GetString(decryptedData);
        }

        public static string Hash(string data)
        {
            using var sha512 = new SHA512Managed();
            return Convert.ToBase64String(sha512.ComputeHash(UTF8.GetBytes(data)));
        }
    }
}
