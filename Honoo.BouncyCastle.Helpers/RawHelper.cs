//using Org.BouncyCastle.Asn1.Pkcs;
//using Org.BouncyCastle.Asn1.X509;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Pkcs;
//using Org.BouncyCastle.Security;
//using Org.BouncyCastle.X509;
//using System;
//using System.Security.Cryptography;

//namespace Honoo.BouncyCastle.Helpers
//{
//    /// <summary>
//    /// Raw helper.
//    /// </summary>
//    public static class RawHelper
//    {
//        /// <summary>
//        /// Convert certificate to raw bytes.
//        /// </summary>
//        /// <param name="cert">Certificate.</param>
//        /// <returns></returns>
//        public static byte[] Cert2Raw(X509Certificate cert)
//        {
//            return cert.GetEncoded();
//        }

//        /// <summary>
//        /// Convert certificate revocation list to raw bytes.
//        /// </summary>
//        /// <param name="crl">Certificate revocation list.</param>
//        /// <returns></returns>
//        public static byte[] Crl2Raw(X509Crl crl)
//        {
//            return crl.GetEncoded();
//        }

//        /// <summary>
//        /// Convert certificate signing request to raw bytes.
//        /// </summary>
//        /// <param name="csr">Certificate signing request.</param>
//        /// <returns></returns>
//        public static byte[] Csr2Raw(Pkcs10CertificationRequest csr)
//        {
//            return csr.GetEncoded();
//        }

//        /// <summary>
//        /// Convert asymmetric key to raw bytes.
//        /// </summary>
//        /// <param name="asymmetricKey">Asymmetric private key or public key.</param>
//        /// <returns></returns>
//        public static byte[] Key2Raw(AsymmetricKeyParameter asymmetricKey)
//        {
//            if (asymmetricKey.IsPrivate)
//            {
//                PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricKey);
//                return info.GetEncoded();
//            }
//            else
//            {
//                SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(asymmetricKey);
//                return info.GetEncoded();
//            }
//        }

//        /// <summary>
//        /// Convert asymmetric private key to raw bytes.
//        /// </summary>
//        /// <param name="privateKey">Asymmetric private key.</param>
//        /// <param name="pbeAlgorithmName">PBE algorithm name.</param>
//        /// <param name="password"></param>
//        /// <param name="salt"></param>
//        /// <param name="iterationCount"></param>
//        /// <returns></returns>
//        public static byte[] Key2Raw(AsymmetricKeyParameter privateKey, PBEAlgorithmName pbeAlgorithmName, string password, byte[] salt, int iterationCount)
//        {
//            string algorithmName;
//            switch (pbeAlgorithmName)
//            {
//                case PBEAlgorithmName.PBEwithHmacRipeMD128: algorithmName = "PBEwithHmacRipeMD128"; break;
//                case PBEAlgorithmName.PBEwithHmacRipeMD160: algorithmName = "PBEwithHmacRipeMD160"; break;
//                case PBEAlgorithmName.PBEwithHmacRipeMD256: algorithmName = "PBEwithHmacRipeMD256"; break;
//                case PBEAlgorithmName.PBEwithHmacSHA_1: algorithmName = "PBEwithHmacSHA-1"; break;
//                case PBEAlgorithmName.PBEwithHmacSHA_224: algorithmName = "PBEwithHmacSHA-224"; break;
//                case PBEAlgorithmName.PBEwithHmacSHA_256: algorithmName = "PBEwithHmacSHA-256"; break;
//                case PBEAlgorithmName.PBEwithMD2andDES_CBC: algorithmName = "PBEwithMD2andDES-CBC"; break;
//                case PBEAlgorithmName.PBEwithMD2andRC2_CBC: algorithmName = "PBEwithMD2andRC2-CBC"; break;
//                case PBEAlgorithmName.PBEwithMD5andDES_CBC: algorithmName = "PBEwithMD5andDES-CBC"; break;
//                case PBEAlgorithmName.PBEwithMD5andRC2_CBC: algorithmName = "PBEwithMD5andRC2-CBC"; break;
//                case PBEAlgorithmName.PBEwithSHA_1and128bitRC2_CBC: algorithmName = "PBEwithSHA-1and128bitRC2-CBC"; break;
//                case PBEAlgorithmName.PBEwithSHA_1and128bitRC4: algorithmName = "PBEwithSHA-1and128bitRC4"; break;
//                case PBEAlgorithmName.PBEwithSHA_1and2_keyDESEDE_CBC: algorithmName = "PBEwithSHA-1and2-keyDESEDE-CBC"; break;
//                case PBEAlgorithmName.PBEwithSHA_1and3_keyDESEDE_CBC: algorithmName = "PBEwithSHA-1and3-keyDESEDE-CBC"; break;
//                case PBEAlgorithmName.PBEwithSHA_1and40bitRC2_CBC: algorithmName = "PBEwithSHA-1and40bitRC2-CBC"; break;
//                case PBEAlgorithmName.PBEwithSHA_1and40bitRC4: algorithmName = "PBEwithSHA-1and40bitRC4"; break;
//                case PBEAlgorithmName.PBEwithSHA_1andDES_CBC: algorithmName = "PBEwithSHA-1andDES-CBC"; break;
//                case PBEAlgorithmName.PBEwithSHA_1andRC2_CBC: algorithmName = "PBEwithSHA-1andRC2-CBC"; break;
//                case PBEAlgorithmName.Pkcs5scheme2: algorithmName = "Pkcs5scheme2"; break;
//                default: throw new CryptographicException("Unsupported PBE algorithm.");
//            }
//            return PrivateKeyFactory.EncryptKey(algorithmName, password.ToCharArray(), salt, iterationCount, privateKey);
//        }

//        /// <summary>
//        /// Convert raw bytes to certificate.
//        /// </summary>
//        /// <param name="raw">Raw bytes.</param>
//        /// <returns></returns>
//        /// <exception cref="Exception"/>
//        public static X509Certificate Raw2Cert(byte[] raw)
//        {
//            return new X509Certificate(raw);
//        }

//        /// <summary>
//        /// Convert raw bytes to certificate revocation list.
//        /// </summary>
//        /// <param name="raw">Raw bytes.</param>
//        /// <returns></returns>
//        /// <exception cref="Exception"/>
//        public static X509Crl Raw2Crl(byte[] raw)
//        {
//            return new X509Crl(raw);
//        }

//        /// <summary>
//        /// Convert raw bytes to certificate signing request.
//        /// </summary>
//        /// <param name="raw">Raw bytes.</param>
//        /// <returns></returns>
//        /// <exception cref="Exception"/>
//        public static Pkcs10CertificationRequest Raw2Csr(byte[] raw)
//        {
//            return new Pkcs10CertificationRequest(raw);
//        }

//        /// <summary>
//        /// Convert raw bytes to asymmetric key.
//        /// </summary>
//        /// <param name="raw">Raw bytes.</param>
//        /// <returns></returns>
//        /// <exception cref="Exception"/>
//        public static AsymmetricKeyParameter Raw2Key(byte[] raw)
//        {
//            try
//            {
//                return PublicKeyFactory.CreateKey(raw);
//            }
//            catch
//            {
//                return PrivateKeyFactory.CreateKey(raw);
//            }
//        }

//        /// <summary>
//        /// Convert raw bytes to asymmetric private key.
//        /// </summary>
//        /// <param name="raw">Raw bytes.</param>
//        /// <param name="password"></param>
//        /// <returns></returns>
//        public static AsymmetricKeyParameter Raw2Key(byte[] raw, string password)
//        {
//            return PrivateKeyFactory.DecryptKey(password.ToCharArray(), raw);
//        }
//    }
//}