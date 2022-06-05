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
        /// Convert asymmetric key pair to pem string.
        /// </summary>
        /// <param name="asymmetricKeyPair">Asymmetric key pair.</param>
        /// <param name="dekAlgorithmName">DEK algorithm name. Select from <see cref="DEKAlgorithmNames"/>.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string KeyPair2Pem(AsymmetricCipherKeyPair asymmetricKeyPair, string dekAlgorithmName, string password)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKeyPair, dekAlgorithmName, password.ToCharArray(), Common.SecureRandom);
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

        /// <summary>
        /// Convert pem string to asymmetric private key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Pem2PrivateKey(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    return (AsymmetricKeyParameter)obj;
                }
                else
                {
                    AsymmetricKeyParameter privateKey = (AsymmetricKeyParameter)obj;
                    if (privateKey.IsPrivate)
                    {
                        return (AsymmetricKeyParameter)obj;
                    }
                    throw new CryptoException("Must be a asymmetric public key pem string.");
                }
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric private key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Pem2PrivateKey(string pem, string password)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                return ((AsymmetricCipherKeyPair)obj).Private;
            }
        }

        /// <summary>
        /// Convert pem string to asymmetric public key.
        /// </summary>
        /// <param name="pem">pem string.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Pem2PublicKey(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    throw new CryptoException("Must be a asymmetric public key pem string.");
                }
                else
                {
                    AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)obj;
                    if (publicKey.IsPrivate)
                    {
                        throw new CryptoException("Must be a asymmetric public key pem string.");
                    }
                    return (AsymmetricKeyParameter)obj;
                }
            }
        }

        /// <summary>
        /// Convert private key to pem string.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        public static string PrivateKey2Pem(AsymmetricKeyParameter privateKey)
        {
            if (privateKey.IsPrivate)
            {
                using (StringWriter writer = new StringWriter())
                {
                    PemWriter pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(privateKey);
                    return writer.ToString();
                }
            }
            throw new CryptoException("Must be a asymmetric private key.");
        }

        /// <summary>
        /// Convert asymmetric private key to pem string.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="dekAlgorithmName">DEK algorithm name. Select from <see cref="DEKAlgorithmNames"/>.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string PrivateKey2Pem(AsymmetricKeyParameter privateKey, string dekAlgorithmName, string password)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(privateKey, dekAlgorithmName, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert public key to pem string.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        public static string PublicKey2Pem(AsymmetricKeyParameter publicKey)
        {
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(publicKey);
                return writer.ToString();
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