    using System;
using System.Text;
using System.Security.Cryptography;

namespace Cyberarms.IntrusionDetection.Shared {
    /// <summary>
    /// WARNING: Uses legacy cryptography (TripleDES, MD5). For sensitive data, upgrade to AES and SHA256 when possible.
    /// </summary>
    internal class CryptoHelper {
        private const string YYHAU_SDBN = "usHN,:_ADs24adH:S";

        /// <summary>
        /// Encrypts a string using TripleDES. Not recommended for new development.
        /// </summary>
        internal static string Encrypt(string toEncrypt, bool useHashing) {
            byte[] keyArray;
            byte[] toEncryptArray = Encoding.UTF8.GetBytes(toEncrypt);
            string key = GetKey();

            if (useHashing) {
                using (var hashmd5 = new MD5CryptoServiceProvider()) {
                    keyArray = hashmd5.ComputeHash(Encoding.UTF8.GetBytes(key));
                }
            } else {
                keyArray = Encoding.UTF8.GetBytes(key);
            }

            using (var tdes = new TripleDESCryptoServiceProvider()) {
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform cTransform = tdes.CreateEncryptor()) {
                    byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                    return Convert.ToBase64String(resultArray, 0, resultArray.Length);
                }
            }
        }

        /// <summary>
        /// Decrypts a string using TripleDES. Not recommended for new development.
        /// </summary>
        internal static string Decrypt(string cipherString, bool useHashing) {
            byte[] keyArray;
            byte[] toEncryptArray = Convert.FromBase64String(cipherString);
            string key = GetKey();

            if (useHashing) {
                using (var hashmd5 = new MD5CryptoServiceProvider()) {
                    keyArray = hashmd5.ComputeHash(Encoding.UTF8.GetBytes(key));
                }
            } else {
                keyArray = Encoding.UTF8.GetBytes(key);
            }

            using (var tdes = new TripleDESCryptoServiceProvider()) {
                tdes.Key = keyArray;
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform cTransform = tdes.CreateDecryptor()) {
                    byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                    return Encoding.UTF8.GetString(resultArray);
                }
            }
        }

        /// <summary>
        /// Retrieves the encryption key. Replace with secure key storage in production.
        /// </summary>
        private static string GetKey() {
            return YYHAU_SDBN;
        }
    }
}
