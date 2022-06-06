using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

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
        public static string Cert2Pem(X509Certificate cert)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(cert);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert certificate revocation list to pem string.
        /// </summary>
        /// <param name="crl">Certificate revocation list.</param>
        /// <returns></returns>
        public static string Crl2Pem(X509Crl crl)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(crl);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert certificate signing request to pem string.
        /// </summary>
        /// <param name="csr">Certificate signing request.</param>
        /// <returns></returns>
        public static string Csr2Pem(Pkcs10CertificationRequest csr)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(csr);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert asymmetric private key to pem string.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="dekAlgorithmName">DEK algorithm name.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string Key2Pem(AsymmetricKeyParameter privateKey, DEKAlgorithmName dekAlgorithmName, string password)
        {
            string algorithmName;
            switch (dekAlgorithmName)
            {
                case DEKAlgorithmName.AES_128_CBC: algorithmName = "AES-128-CBC"; break;
                case DEKAlgorithmName.AES_128_CFB: algorithmName = "AES-128-CFB"; break;
                case DEKAlgorithmName.AES_128_ECB: algorithmName = "AES-128-ECB"; break;
                case DEKAlgorithmName.AES_128_OFB: algorithmName = "AES-128-OFB"; break;
                case DEKAlgorithmName.AES_192_CBC: algorithmName = "AES-192-CBC"; break;
                case DEKAlgorithmName.AES_192_CFB: algorithmName = "AES-192-CFB"; break;
                case DEKAlgorithmName.AES_192_ECB: algorithmName = "AES-192-ECB"; break;
                case DEKAlgorithmName.AES_192_OFB: algorithmName = "AES-192-OFB"; break;
                case DEKAlgorithmName.AES_256_CBC: algorithmName = "AES-256-CBC"; break;
                case DEKAlgorithmName.AES_256_CFB: algorithmName = "AES-256-CFB"; break;
                case DEKAlgorithmName.AES_256_ECB: algorithmName = "AES-256-ECB"; break;
                case DEKAlgorithmName.AES_256_OFB: algorithmName = "AES-256-OFB"; break;
                case DEKAlgorithmName.BLOWFISH_CBC: algorithmName = "BF-CBC"; break;
                case DEKAlgorithmName.BLOWFISH_CFB: algorithmName = "BF-CFB"; break;
                case DEKAlgorithmName.BLOWFISH_ECB: algorithmName = "BF-ECB"; break;
                case DEKAlgorithmName.BLOWFISH_OFB: algorithmName = "BF-OFB"; break;
                case DEKAlgorithmName.DES_CBC: algorithmName = "DES-CBC"; break;
                case DEKAlgorithmName.DES_CFB: algorithmName = "DES-CFB"; break;
                case DEKAlgorithmName.DES_ECB: algorithmName = "DES-ECB"; break;
                case DEKAlgorithmName.DES_OFB: algorithmName = "DES-OFB"; break;
                case DEKAlgorithmName.DES_EDE_CBC: algorithmName = "DES-EDE-CBC"; break;
                case DEKAlgorithmName.DES_EDE_CFB: algorithmName = "DES-EDE-CFB"; break;
                case DEKAlgorithmName.DES_EDE_ECB: algorithmName = "DES-EDE-ECB"; break;
                case DEKAlgorithmName.DES_EDE_OFB: algorithmName = "DES-EDE-OFB"; break;
                case DEKAlgorithmName.DES_EDE3_CBC: algorithmName = "DES-EDE3-CBC"; break;
                case DEKAlgorithmName.DES_EDE3_CFB: algorithmName = "DES-EDE3-CFB"; break;
                case DEKAlgorithmName.DES_EDE3_ECB: algorithmName = "DES-EDE3-ECB"; break;
                case DEKAlgorithmName.DES_EDE3_OFB: algorithmName = "DES-EDE3-OFB"; break;
                case DEKAlgorithmName.RC2_40_CBC: algorithmName = "RC2-40-CBC"; break;
                case DEKAlgorithmName.RC2_40_CFB: algorithmName = "RC2-40-CFB"; break;
                case DEKAlgorithmName.RC2_40_ECB: algorithmName = "RC2-40-ECB"; break;
                case DEKAlgorithmName.RC2_40_OFB: algorithmName = "RC2-40-OFB"; break;
                case DEKAlgorithmName.RC2_64_CBC: algorithmName = "RC2-64-CBC"; break;
                case DEKAlgorithmName.RC2_64_CFB: algorithmName = "RC2-64-CFB"; break;
                case DEKAlgorithmName.RC2_64_ECB: algorithmName = "RC2-64-ECB"; break;
                case DEKAlgorithmName.RC2_64_OFB: algorithmName = "RC2-64-OFB"; break;
                case DEKAlgorithmName.RC2_CBC: algorithmName = "RC2-CBC"; break;
                case DEKAlgorithmName.RC2_CFB: algorithmName = "RC2-CFB"; break;
                case DEKAlgorithmName.RC2_ECB: algorithmName = "RC2-ECB"; break;
                case DEKAlgorithmName.RC2_OFB: algorithmName = "RC2-OFB"; break;
                default: throw new CryptographicException("Unsupported DEK algorithm.");
            }
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(privateKey, algorithmName, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert asymmetric key to pem string.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric private key or public key.</param>
        /// <returns></returns>
        public static string Key2Pem(AsymmetricKeyParameter asymmetricKey)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKey);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert asymmetric key pair to pem string.
        /// </summary>
        /// <param name="asymmetricKeyPair">Asymmetric key pair.</param>
        /// <param name="dekAlgorithmName">DEK algorithm name.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string KeyPair2Pem(AsymmetricCipherKeyPair asymmetricKeyPair, DEKAlgorithmName dekAlgorithmName, string password)
        {
            string algorithmName;
            switch (dekAlgorithmName)
            {
                case DEKAlgorithmName.AES_128_CBC: algorithmName = "AES-128-CBC"; break;
                case DEKAlgorithmName.AES_128_CFB: algorithmName = "AES-128-CFB"; break;
                case DEKAlgorithmName.AES_128_ECB: algorithmName = "AES-128-ECB"; break;
                case DEKAlgorithmName.AES_128_OFB: algorithmName = "AES-128-OFB"; break;
                case DEKAlgorithmName.AES_192_CBC: algorithmName = "AES-192-CBC"; break;
                case DEKAlgorithmName.AES_192_CFB: algorithmName = "AES-192-CFB"; break;
                case DEKAlgorithmName.AES_192_ECB: algorithmName = "AES-192-ECB"; break;
                case DEKAlgorithmName.AES_192_OFB: algorithmName = "AES-192-OFB"; break;
                case DEKAlgorithmName.AES_256_CBC: algorithmName = "AES-256-CBC"; break;
                case DEKAlgorithmName.AES_256_CFB: algorithmName = "AES-256-CFB"; break;
                case DEKAlgorithmName.AES_256_ECB: algorithmName = "AES-256-ECB"; break;
                case DEKAlgorithmName.AES_256_OFB: algorithmName = "AES-256-OFB"; break;
                case DEKAlgorithmName.BLOWFISH_CBC: algorithmName = "BF-CBC"; break;
                case DEKAlgorithmName.BLOWFISH_CFB: algorithmName = "BF-CFB"; break;
                case DEKAlgorithmName.BLOWFISH_ECB: algorithmName = "BF-ECB"; break;
                case DEKAlgorithmName.BLOWFISH_OFB: algorithmName = "BF-OFB"; break;
                case DEKAlgorithmName.DES_CBC: algorithmName = "DES-CBC"; break;
                case DEKAlgorithmName.DES_CFB: algorithmName = "DES-CFB"; break;
                case DEKAlgorithmName.DES_ECB: algorithmName = "DES-ECB"; break;
                case DEKAlgorithmName.DES_OFB: algorithmName = "DES-OFB"; break;
                case DEKAlgorithmName.DES_EDE_CBC: algorithmName = "DES-EDE-CBC"; break;
                case DEKAlgorithmName.DES_EDE_CFB: algorithmName = "DES-EDE-CFB"; break;
                case DEKAlgorithmName.DES_EDE_ECB: algorithmName = "DES-EDE-ECB"; break;
                case DEKAlgorithmName.DES_EDE_OFB: algorithmName = "DES-EDE-OFB"; break;
                case DEKAlgorithmName.DES_EDE3_CBC: algorithmName = "DES-EDE3-CBC"; break;
                case DEKAlgorithmName.DES_EDE3_CFB: algorithmName = "DES-EDE3-CFB"; break;
                case DEKAlgorithmName.DES_EDE3_ECB: algorithmName = "DES-EDE3-ECB"; break;
                case DEKAlgorithmName.DES_EDE3_OFB: algorithmName = "DES-EDE3-OFB"; break;
                case DEKAlgorithmName.RC2_40_CBC: algorithmName = "RC2-40-CBC"; break;
                case DEKAlgorithmName.RC2_40_CFB: algorithmName = "RC2-40-CFB"; break;
                case DEKAlgorithmName.RC2_40_ECB: algorithmName = "RC2-40-ECB"; break;
                case DEKAlgorithmName.RC2_40_OFB: algorithmName = "RC2-40-OFB"; break;
                case DEKAlgorithmName.RC2_64_CBC: algorithmName = "RC2-64-CBC"; break;
                case DEKAlgorithmName.RC2_64_CFB: algorithmName = "RC2-64-CFB"; break;
                case DEKAlgorithmName.RC2_64_ECB: algorithmName = "RC2-64-ECB"; break;
                case DEKAlgorithmName.RC2_64_OFB: algorithmName = "RC2-64-OFB"; break;
                case DEKAlgorithmName.RC2_CBC: algorithmName = "RC2-CBC"; break;
                case DEKAlgorithmName.RC2_CFB: algorithmName = "RC2-CFB"; break;
                case DEKAlgorithmName.RC2_ECB: algorithmName = "RC2-ECB"; break;
                case DEKAlgorithmName.RC2_OFB: algorithmName = "RC2-OFB"; break;
                default: throw new CryptographicException("Unsupported DEK algorithm.");
            }
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKeyPair, algorithmName, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert asymmetric key pair to pem string.
        /// </summary>
        /// <param name="asymmetricKeyPair">Asymmetric key pair.</param>
        /// <returns></returns>
        public static string KeyPair2Pem(AsymmetricCipherKeyPair asymmetricKeyPair)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKeyPair);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert pem string to certificate.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate Pem2Cert(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (X509Certificate)obj;
            }
        }

        /// <summary>
        /// Convert pem string to certificate revocation list.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Crl Pem2Crl(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (X509Crl)obj;
            }
        }

        /// <summary>
        /// Convert pem string to certificate signing request.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest Pem2Csr(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                return (Pkcs10CertificationRequest)obj;
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric private key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Pem2Key(string pem, string password)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                return ((AsymmetricCipherKeyPair)obj).Private;
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Pem2Key(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    return ((AsymmetricCipherKeyPair)obj).Private;
                }
                else
                {
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
        public static AsymmetricCipherKeyPair Pem2KeyPair(string pem)
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
        public static AsymmetricCipherKeyPair Pem2KeyPair(string pem, string password)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                return (AsymmetricCipherKeyPair)obj;
            }
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