using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Pem helper.
    /// </summary>
    public static class PemHelper
    {
        /// <summary>
        /// Convert certificate to pem string.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <returns></returns>
        public static string CertToPem(X509Certificate cert)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(cert);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert certificate signing request to pem string.
        /// </summary>
        /// <param name="csr">Certificate signing request.</param>
        /// <returns></returns>
        public static string CsrToPem(Pkcs10CertificationRequest csr)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(csr);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert asymmetric key to pem string.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        public static string KeyToPem(AsymmetricKeyParameter asymmetricKey)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKey);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert asymmetric key to pem string.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="dekAlgorithmName">DEK algorithm name. Select from <see cref="DEKAlgorithmNames"/>.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string KeyToPem(AsymmetricKeyParameter privateKey, string dekAlgorithmName, string password)
        {
            if (string.IsNullOrEmpty(dekAlgorithmName))
            {
                throw new ArgumentNullException(nameof(dekAlgorithmName));
            }
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);

                pemWriter.WriteObject(privateKey, dekAlgorithmName, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert pem string to certificate.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate PemToCert(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (X509Certificate)obj;
            }
        }

        /// <summary>
        /// Convert pem string to certificate signing request.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest PemToCsr(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (Pkcs10CertificationRequest)obj;
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter PemToKey(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (AsymmetricKeyParameter)obj;
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter PemToKey(string pem, string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return PemToKey(pem);
            }
            else
            {
                using (StringReader reader = new StringReader(pem))
                {
                    object obj = new PemReader(reader, new Password(password)).ReadObject();
                    return (AsymmetricKeyParameter)obj;
                }
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric key pair.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricCipherKeyPair PemToKeyPair(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (AsymmetricCipherKeyPair)obj;
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric key pair.
        /// </summary>
        /// <param name="pem">Pem string.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static AsymmetricCipherKeyPair PemToKeyPair(string pem, string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return PemToKeyPair(pem);
            }
            else
            {
                using (StringReader reader = new StringReader(pem))
                {
                    object obj = new PemReader(reader, new Password(password)).ReadObject();
                    return (AsymmetricCipherKeyPair)obj;
                }
            }
        }

        /// <summary>
        /// DEK algorithm names.
        /// </summary>
        public static class DEKAlgorithmNames
        {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

            public const string AES_128_CBC = "AES-128-CBC";
            public const string AES_128_ECB = "AES-128-ECB";
            public const string AES_192_CBC = "AES-192-CBC";
            public const string AES_192_ECB = "AES-192-ECB";
            public const string AES_256_CBC = "AES-256-CBC";
            public const string AES_256_ECB = "AES-256-ECB";
            public const string BLOWFISH_CBC = "BLOWFISH-CBC";
            public const string BLOWFISH_ECB = "BLOWFISH-ECB";
            public const string DES_CBC = "DES-CBC";
            public const string DES_ECB = "DES-ECB";
            public const string DES_EDE_CBC = "DES-EDE-CBC";
            public const string DES_EDE_ECB = "DES-EDE-ECB";
            public const string DES_EDE3_CBC = "DES-EDE3-CBC";
            public const string DES_EDE3_ECB = "DES-EDE3-ECB";
            public const string RC2_40_CBC = "RC2-40-CBC";
            public const string RC2_40_ECB = "RC2-40-ECB";
            public const string RC2_64_CBC = "RC2-64-CBC";
            public const string RC2_64_ECB = "RC2-64-ECB";
            public const string RC2_CBC = "RC2-CBC";
            public const string RC2_ECB = "RC2-ECB";

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
        }

        internal sealed class Password : IPasswordFinder
        {
            private readonly char[] _chars;

            internal Password(string password)
            {
                _chars = password.ToCharArray();
            }

            /// <summary></summary>
            /// <returns></returns>
            public char[] GetPassword()
            {
                return _chars;
            }
        }
    }
}