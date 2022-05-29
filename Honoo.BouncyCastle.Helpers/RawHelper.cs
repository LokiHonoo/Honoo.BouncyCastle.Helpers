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
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        public static byte[] Key2Raw(AsymmetricKeyParameter publicKey)
        {
            if (publicKey.IsPrivate)
            {
                //PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricKey);
                //return info.GetEncoded();
                throw new InvalidKeyException("Saving a private key is not supported.");
            }
            else
            {
                SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                return info.GetEncoded();
            }
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
        /// Convert raw bytes to asymmetric public key.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static AsymmetricKeyParameter Raw2Key(byte[] raw)
        {
            return PublicKeyFactory.CreateKey(raw);
        }
    }
}