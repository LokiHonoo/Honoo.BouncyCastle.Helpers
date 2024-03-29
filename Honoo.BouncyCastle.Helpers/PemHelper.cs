﻿using Org.BouncyCastle.Crypto;
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
        /// Convert asymmetric private key to pem string.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="dekAlgorithmName">DEK algorithm name.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string Key2Pem(AsymmetricKeyParameter privateKey, DEKAlgorithmName dekAlgorithmName, string password)
        {
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(privateKey, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom);
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
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKeyPair, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom);
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