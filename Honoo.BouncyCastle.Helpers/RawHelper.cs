using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Raw helper.
    /// </summary>
    public static class RawHelper
    {
        /// <summary>
        /// Convert certificate to raw bytes.
        /// </summary>
        /// <param name="cert">Certificate.</param>
        /// <returns></returns>
        public static byte[] Cert2Raw(X509Certificate cert)
        {
            return cert.GetEncoded();
        }

        /// <summary>
        /// Convert certificate revocation list to raw bytes.
        /// </summary>
        /// <param name="crl">Certificate revocation list.</param>
        /// <returns></returns>
        public static byte[] Crl2Raw(X509Crl crl)
        {
            return crl.GetEncoded();
        }

        /// <summary>
        /// Convert certificate signing request to raw bytes.
        /// </summary>
        /// <param name="csr">Certificate signing request.</param>
        /// <returns></returns>
        public static byte[] Csr2Raw(Pkcs10CertificationRequest csr)
        {
            return csr.GetEncoded();
        }

        /// <summary>
        /// Convert asymmetric public key to raw bytes.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        public static byte[] Key2Raw(AsymmetricKeyParameter asymmetricKey)
        {
            if (asymmetricKey.IsPrivate)
            {
                PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricKey);
                return info.GetEncoded();
            }
            else
            {
                SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(asymmetricKey);
                return info.GetEncoded();
            }
        }

        /// <summary>
        /// Convert asymmetric public key to raw bytes.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="pbeAlgorithmName">PBE algorithm name. Select from <see cref="PBEAlgorithmNames"/>.</param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="iterationCount"></param>
        /// <returns></returns>
        public static byte[] PrivateKey2Raw(AsymmetricKeyParameter privateKey, string pbeAlgorithmName, string password, byte[] salt, int iterationCount)
        {
            return PrivateKeyFactory.EncryptKey(pbeAlgorithmName, password.ToCharArray(), salt, iterationCount, privateKey);
        }

        /// <summary>
        /// Convert raw bytes to certificate.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate Raw2Cert(byte[] raw)
        {
            return new X509Certificate(raw);
        }

        /// <summary>
        /// Convert raw bytes to certificate revocation list.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Crl Raw2Crl(byte[] raw)
        {
            return new X509Crl(raw);
        }

        /// <summary>
        /// Convert raw bytes to certificate signing request.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest Raw2Csr(byte[] raw)
        {
            return new Pkcs10CertificationRequest(raw);
        }

        /// <summary>
        /// Convert raw bytes to asymmetric key.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <param name="isPrivate">Indicates that raw is a private key data.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Raw2Key(byte[] raw, bool isPrivate)
        {
            return isPrivate ? PrivateKeyFactory.CreateKey(raw) : PublicKeyFactory.CreateKey(raw);
        }

        /// <summary>
        /// Convert raw bytes to asymmetric private key.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter Raw2PrivateKey(byte[] raw, string password)
        {
            return PrivateKeyFactory.DecryptKey(password.ToCharArray(), raw);
        }

        /// <summary>
        /// PBE algorithm names.
        /// </summary>
        public static class PBEAlgorithmNames
        {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释
            public const string PBEwithHmacRipeMD128 = "PBEwithHmacRipeMD128";
            public const string PBEwithHmacRipeMD160 = "PBEwithHmacRipeMD160";
            public const string PBEwithHmacRipeMD256 = "PBEwithHmacRipeMD256";
            public const string PBEwithHmacSHA_1 = "PBEwithHmacSHA-1";
            public const string PBEwithHmacSHA_224 = "PBEwithHmacSHA-224";
            public const string PBEwithHmacSHA_256 = "PBEwithHmacSHA-256";
            public const string PBEwithMD2andDES_CBC = "PBEwithMD2andDES-CBC";
            public const string PBEwithMD2andRC2_CBC = "PBEwithMD2andRC2-CBC";
            public const string PBEwithMD5andDES_CBC = "PBEwithMD5andDES-CBC";
            public const string PBEwithMD5andRC2_CBC = "PBEwithMD5andRC2-CBC";
            public const string PBEwithSHA_1and128bitRC2_CBC = "PBEwithSHA-1and128bitRC2-CBC";
            public const string PBEwithSHA_1and128bitRC4 = "PBEwithSHA-1and128bitRC4";
            public const string PBEwithSHA_1and2_keyDESEDE_CBC = "PBEwithSHA-1and2-keyDESEDE-CBC";
            public const string PBEwithSHA_1and3_keyDESEDE_CBC = "PBEwithSHA-1and3-keyDESEDE-CBC";
            public const string PBEwithSHA_1and40bitRC2_CBC = "PBEwithSHA-1and40bitRC2-CBC";
            public const string PBEwithSHA_1and40bitRC4 = "PBEwithSHA-1and40bitRC4";
            public const string PBEwithSHA_1andDES_CBC = "PBEwithSHA-1andDES-CBC";
            public const string PBEwithSHA_1andRC2_CBC = "PBEwithSHA-1andRC2-CBC";
            public const string Pkcs5scheme2 = "Pkcs5scheme2";
#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
        }
    }
}