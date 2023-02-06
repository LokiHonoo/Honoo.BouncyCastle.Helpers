using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// X509 helper.
    /// </summary>
    public static class X509Helper
    {
        /// <summary>
        /// Extract certificate signing request.
        /// </summary>
        /// <param name="csr">Certificate signing request.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="dn">Distinct name.</param>
        /// <param name="extensions">Extensions.</param>
        /// <exception cref="Exception"/>
        public static void ExtractCsr(Pkcs10CertificationRequest csr,
                                      out AsymmetricKeyParameter publicKey,
                                      out IList<X509NameEntity> dn,
                                      out IList<X509ExtensionEntity> extensions)
        {
            if (csr == null)
            {
                throw new ArgumentNullException(nameof(csr));
            }
            publicKey = csr.GetPublicKey();
            CertificationRequestInfo csrInfo = csr.GetCertificationRequestInfo();
            dn = new List<X509NameEntity>();
            IList oids = csrInfo.Subject.GetOidList();
            IList values = csrInfo.Subject.GetValueList();
            for (int i = 0; i < oids.Count; i++)
            {
                dn.Add(new X509NameEntity((DerObjectIdentifier)oids[i], (string)values[i]));
            }
            if (csrInfo.Attributes != null)
            {
                extensions = new List<X509ExtensionEntity>();
                foreach (AttributePkcs attribute in csrInfo.Attributes)
                {
                    if (attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                    {
                        foreach (X509Extensions exts in attribute.AttrValues)
                        {
                            foreach (DerObjectIdentifier oid in exts.ExtensionOids)
                            {
                                X509Extension ext = exts.GetExtension(oid);
                                extensions.Add(new X509ExtensionEntity(oid, ext.IsCritical, ext.Value));
                            }
                        }
                    }
                }
                //Dictionary<DerObjectIdentifier, X509Extension> attributes = new Dictionary<DerObjectIdentifier, X509Extension>();
                //foreach (AttributePkcs attribute in csrInfo.Attributes)
                //{
                //    if (attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                //    {
                //        foreach (X509Extensions exts in attribute.AttrValues)
                //        {
                //            foreach (DerObjectIdentifier oid in exts.ExtensionOids)
                //            {
                //                X509Extension ext = exts.GetExtension(oid);
                //                attributes.Add(oid, new X509Extension(ext.IsCritical, ext.Value));
                //            }
                //        }
                //    }
                //}
                //X509Extensions x509Extensions = new X509Extensions(attributes);
            }
            else
            {
                extensions = null;
            }
        }

        /// <summary>
        /// Generate certificate revocation list.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm supported by x590.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="issuerCertificate">The certificate of issuer.</param>
        /// <param name="revocations">Revocation certificates.</param>
        /// <param name="extensions">Extensions.</param>
        /// <param name="thisUpdate"></param>
        /// <param name="nextUpdate"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Crl GenerateCrl(ISignatureAlgorithm signatureAlgorithm,
                                          AsymmetricKeyParameter privateKey,
                                          X509Certificate issuerCertificate,
                                          IList<X509RevocationEntity> revocations,
                                          IList<X509ExtensionEntity> extensions,
                                          DateTime thisUpdate,
                                          DateTime nextUpdate)
        {
            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }
            if (signatureAlgorithm.Oid == null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                return GenerateCrl(signatureAlgorithm.Oid.Id, privateKey, issuerCertificate.SubjectDN, revocations, extensions, thisUpdate, nextUpdate);
            }
        }

        /// <summary>
        /// Generate certificate revocation list.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm name or oid supported by x590.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="issuerCertificate">The certificate of issuer.</param>
        /// <param name="revocations">Revocation certificates.</param>
        /// <param name="extensions">Extensions.</param>
        /// <param name="thisUpdate"></param>
        /// <param name="nextUpdate"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Crl GenerateCrl(string signatureAlgorithm,
                                          AsymmetricKeyParameter privateKey,
                                          X509Certificate issuerCertificate,
                                          IList<X509RevocationEntity> revocations,
                                          IList<X509ExtensionEntity> extensions,
                                          DateTime thisUpdate,
                                          DateTime nextUpdate)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }
            if (SignatureAlgorithmHelper.TryGetAlgorithm(signatureAlgorithm, out ISignatureAlgorithm algorithm))
            {
                return GenerateCrl(algorithm.Oid.Id, privateKey, issuerCertificate.SubjectDN, revocations, extensions, thisUpdate, nextUpdate);
            }
            else
            {
                throw new ArgumentException("Unsupported signature algorithm.", signatureAlgorithm);
            }
        }

        /// <summary>
        /// Generate certificate signing request.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm supported by x590.</param>
        /// <param name="asymmetricKeyPair">Asymmetric key pair.</param>
        /// <param name="dn">Distinct name.</param>
        /// <param name="extensions">Extensions.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest GenerateCsr(ISignatureAlgorithm signatureAlgorithm,
                                                             AsymmetricCipherKeyPair asymmetricKeyPair,
                                                             IList<X509NameEntity> dn,
                                                             IList<X509ExtensionEntity> extensions)
        {
            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (asymmetricKeyPair == null)
            {
                throw new ArgumentNullException(nameof(asymmetricKeyPair));
            }
            if (dn == null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (signatureAlgorithm.Oid == null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                return GenerateCsr(signatureAlgorithm.Oid.Id, asymmetricKeyPair, dn, extensions);
            }
        }

        /// <summary>
        /// Generate certificate signing request.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm name or oid supported by x590.</param>
        /// <param name="asymmetricKeyPair">Asymmetric key pair.</param>
        /// <param name="dn">Distinct name.</param>
        /// <param name="extensions">Extensions.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest GenerateCsr(string signatureAlgorithm,
                                                             AsymmetricCipherKeyPair asymmetricKeyPair,
                                                             IList<X509NameEntity> dn,
                                                             IList<X509ExtensionEntity> extensions)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (asymmetricKeyPair == null)
            {
                throw new ArgumentNullException(nameof(asymmetricKeyPair));
            }
            if (dn == null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (SignatureAlgorithmHelper.TryGetAlgorithm(signatureAlgorithm, out ISignatureAlgorithm algorithm))
            {
                Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm.Oid.Id, asymmetricKeyPair.Private, Common.SecureRandom);
                DerSet attribute = extensions == null ? null
                    : new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(GenerateX509Extensions(extensions))));
                return new Pkcs10CertificationRequest(signatureFactory, GenerateX509Name(dn), asymmetricKeyPair.Public, attribute);
            }
            else
            {
                throw new ArgumentException("Unsupported signature algorithm.", signatureAlgorithm);
            }
        }

        /// <summary>
        /// Generate issuer self signed certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm supported by x590.</param>
        /// <param name="asymmetricKeyPair">The asymmetric key pair of issuer.</param>
        /// <param name="dn">The distinct name of issuer.</param>
        /// <param name="extensions">Extensions of issuer.</param>
        /// <param name="start">The start time.</param>
        /// <param name="end">The end time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateIssuerCertificate(ISignatureAlgorithm signatureAlgorithm,
                                                                AsymmetricCipherKeyPair asymmetricKeyPair,
                                                                IList<X509NameEntity> dn,
                                                                IList<X509ExtensionEntity> extensions,
                                                                DateTime start,
                                                                DateTime end)
        {
            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (asymmetricKeyPair == null)
            {
                throw new ArgumentNullException(nameof(asymmetricKeyPair));
            }
            if (dn == null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (signatureAlgorithm.Oid == null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                X509Name dn_ = GenerateX509Name(dn);
                return GenerateCertificate(signatureAlgorithm.Oid.Id, asymmetricKeyPair.Private, dn_, asymmetricKeyPair.Public, dn_, extensions, start, end);
            }
        }

        /// <summary>
        /// Generate issuer self signed certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm name or oid supported by x590.</param>
        /// <param name="asymmetricKeyPair">The asymmetric key pair of issuer.</param>
        /// <param name="dn">The distinct name of issuer.</param>
        /// <param name="extensions">Extensions of issuer.</param>
        /// <param name="start">The start time.</param>
        /// <param name="end">The end time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateIssuerCertificate(string signatureAlgorithm,
                                                                AsymmetricCipherKeyPair asymmetricKeyPair,
                                                                IList<X509NameEntity> dn,
                                                                IList<X509ExtensionEntity> extensions,
                                                                DateTime start,
                                                                DateTime end)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (asymmetricKeyPair == null)
            {
                throw new ArgumentNullException(nameof(asymmetricKeyPair));
            }
            if (dn == null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (SignatureAlgorithmHelper.TryGetAlgorithm(signatureAlgorithm, out ISignatureAlgorithm algorithm))
            {
                X509Name dn_ = GenerateX509Name(dn);
                return GenerateCertificate(algorithm.Oid.Id, asymmetricKeyPair.Private, dn_, asymmetricKeyPair.Public, dn_, extensions, start, end);
            }
            else
            {
                throw new ArgumentException("Unsupported signature algorithm.", signatureAlgorithm);
            }
        }

        /// <summary>
        /// Generate Pkcs#12 certificate.
        /// </summary>
        /// <param name="output">Output stream.</param>
        /// <param name="privateKeyAlias">The alias of private key.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="chain">Chain collection for private key.</param>
        /// <param name="certificateAlias">The alias of certificate.</param>
        /// <param name="certificate">Certificate.</param>
        /// <param name="password">Password.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static void GeneratePkcs12(Stream output,
                                          string privateKeyAlias,
                                          AsymmetricKeyParameter privateKey,
                                          IList<X509Certificate> chain,
                                          string certificateAlias,
                                          X509Certificate certificate,
                                          string password)
        {
            if (output is null)
            {
                throw new ArgumentNullException(nameof(output));
            }
            if (string.IsNullOrWhiteSpace(privateKeyAlias))
            {
                throw new ArgumentNullException(nameof(privateKeyAlias));
            }
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (chain == null)
            {
                throw new ArgumentNullException(nameof(chain));
            }
            if (chain.Count == 0)
            {
                throw new ArgumentNullException(nameof(chain));
            }
            if (password == null)
            {
                password = string.Empty;
            }
            Pkcs12StoreBuilder builder = new Pkcs12StoreBuilder();
            // builder =  builder.SetKeyAlgorithm(keyAlgorithmName.Oid);
            // builder = builder.SetCertAlgorithm(certificateAlgorithmName.Oid);
            Pkcs12Store pkcs12 = builder.Build();
            List<X509CertificateEntry> certEntries = new List<X509CertificateEntry>();
            foreach (X509Certificate cert in chain)
            {
                certEntries.Add(new X509CertificateEntry(cert));
            }
            pkcs12.SetKeyEntry(privateKeyAlias, new AsymmetricKeyEntry(privateKey), certEntries.ToArray());

            if (!string.IsNullOrWhiteSpace(certificateAlias) && certificate != null)
            {
                pkcs12.SetCertificateEntry(certificateAlias, new X509CertificateEntry(certificate));
            }
            pkcs12.Save(output, password.ToCharArray(), Common.SecureRandom);
        }

        /// <summary>
        /// Generate subject certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm supported by x590.</param>
        /// <param name="issuerPrivateKey">The asymmetric private key of issuer.</param>
        /// <param name="issuerCertificate">The certificate of issuer.</param>
        /// <param name="subjectPublicKey">The asymmetric public key of subject.</param>
        /// <param name="subjectDN">The distinct name of subject.</param>
        /// <param name="subjectExtensions">Extensions of subject.</param>
        /// <param name="start">The start time.</param>
        /// <param name="end">The end time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateSubjectCertificate(ISignatureAlgorithm signatureAlgorithm,
                                                                 AsymmetricKeyParameter issuerPrivateKey,
                                                                 X509Certificate issuerCertificate,
                                                                 AsymmetricKeyParameter subjectPublicKey,
                                                                 IList<X509NameEntity> subjectDN,
                                                                 IList<X509ExtensionEntity> subjectExtensions,
                                                                 DateTime start,
                                                                 DateTime end)
        {
            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (issuerPrivateKey == null)
            {
                throw new ArgumentNullException(nameof(issuerPrivateKey));
            }
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }
            if (subjectPublicKey == null)
            {
                throw new ArgumentNullException(nameof(subjectPublicKey));
            }
            if (subjectDN == null)
            {
                throw new ArgumentNullException(nameof(subjectDN));
            }
            try
            {
                issuerCertificate.CheckValidity();
            }
            catch
            {
                throw new CryptographicException("The issuer's certificate has expired.");
            }
            try
            {
                issuerCertificate.CheckValidity(end);
            }
            catch
            {
                throw new CryptographicException("The end time exceeds the validity of the issuer certificate.");
            }
            if (signatureAlgorithm.Oid == null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                return GenerateCertificate(signatureAlgorithm.Oid.Id,
                                           issuerPrivateKey,
                                           issuerCertificate.SubjectDN,
                                           subjectPublicKey,
                                           GenerateX509Name(subjectDN),
                                           subjectExtensions,
                                           start,
                                           end);
            }
        }

        /// <summary>
        /// Generate subject certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm name or oid supported by x590.</param>
        /// <param name="issuerPrivateKey">The asymmetric private key of issuer.</param>
        /// <param name="issuerCertificate">The certificate of issuer.</param>
        /// <param name="subjectPublicKey">The asymmetric public key of subject.</param>
        /// <param name="subjectDN">The distinct name of subject.</param>
        /// <param name="subjectExtensions">Extensions of subject.</param>
        /// <param name="start">The start time.</param>
        /// <param name="end">The end time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateSubjectCertificate(string signatureAlgorithm,
                                                                 AsymmetricKeyParameter issuerPrivateKey,
                                                                 X509Certificate issuerCertificate,
                                                                 AsymmetricKeyParameter subjectPublicKey,
                                                                 IList<X509NameEntity> subjectDN,
                                                                 IList<X509ExtensionEntity> subjectExtensions,
                                                                 DateTime start,
                                                                 DateTime end)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (issuerPrivateKey == null)
            {
                throw new ArgumentNullException(nameof(issuerPrivateKey));
            }
            if (issuerCertificate == null)
            {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }
            if (subjectPublicKey == null)
            {
                throw new ArgumentNullException(nameof(subjectPublicKey));
            }
            if (subjectDN == null)
            {
                throw new ArgumentNullException(nameof(subjectDN));
            }
            try
            {
                issuerCertificate.CheckValidity();
            }
            catch
            {
                throw new CryptographicException("The issuer's certificate has expired.");
            }
            try
            {
                issuerCertificate.CheckValidity(end);
            }
            catch
            {
                throw new CryptographicException("The end time exceeds the validity of the issuer certificate.");
            }
            if (SignatureAlgorithmHelper.TryGetAlgorithm(signatureAlgorithm, out ISignatureAlgorithm algorithm))
            {
                return GenerateCertificate(algorithm.Oid.Id,
                                           issuerPrivateKey,
                                           issuerCertificate.SubjectDN,
                                           subjectPublicKey,
                                           GenerateX509Name(subjectDN),
                                           subjectExtensions,
                                           start,
                                           end);
            }
            else
            {
                throw new ArgumentException("Unsupported signature algorithm.", signatureAlgorithm);
            }
        }

        /// <summary>
        /// Read Pkcs#12 certificate.
        /// </summary>
        /// <param name="input">Input stream.</param>
        /// <param name="password">Password.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs12Store ReadPkcs12(Stream input, string password)
        {
            if (input is null)
            {
                throw new ArgumentNullException(nameof(input));
            }
            if (password == null)
            {
                password = string.Empty;
            }
            return new Pkcs12Store(input, password.ToCharArray());
        }

        private static X509Certificate GenerateCertificate(string signatureAlgorithmOid,
                                                           AsymmetricKeyParameter issuerPrivateKey,
                                                           X509Name issuerDN,
                                                           AsymmetricKeyParameter subjectPublicKey,
                                                           X509Name subjectDN,
                                                           IList<X509ExtensionEntity> subjectExtensions,
                                                           DateTime start,
                                                           DateTime end)
        {
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithmOid, issuerPrivateKey, Common.SecureRandom);
            BigInteger sn = new BigInteger(128, Common.SecureRandom);
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(sn);
            generator.SetIssuerDN(issuerDN);
            generator.SetPublicKey(subjectPublicKey);
            generator.SetSubjectDN(subjectDN);
            if (subjectExtensions != null)
            {
                foreach (X509ExtensionEntity extension in subjectExtensions)
                {
                    generator.AddExtension(extension.Oid, extension.IsCritical, extension.Value);
                }
            }
            generator.SetNotBefore(start);
            generator.SetNotAfter(end);
            return generator.Generate(signatureFactory);
        }

        private static X509Crl GenerateCrl(string signatureAlgorithmOid,
                                           AsymmetricKeyParameter privateKey,
                                           X509Name dn,
                                           IList<X509RevocationEntity> revocations,
                                           IList<X509ExtensionEntity> extensions,
                                           DateTime thisUpdate,
                                           DateTime nextUpdate)
        {
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithmOid, privateKey, Common.SecureRandom);
            X509V2CrlGenerator generator = new X509V2CrlGenerator();
            generator.SetIssuerDN(dn);
            if (revocations != null)
            {
                foreach (X509RevocationEntity rvocationEntry in revocations)
                {
                    generator.AddCrlEntry(rvocationEntry.SerialNumber, rvocationEntry.RevocationDate, rvocationEntry.Extensions);
                }
            }
            if (extensions != null)
            {
                foreach (X509ExtensionEntity extension in extensions)
                {
                    generator.AddExtension(extension.Oid, extension.IsCritical, extension.Value);
                }
            }

            generator.SetThisUpdate(thisUpdate);
            generator.SetNextUpdate(nextUpdate);
            return generator.Generate(signatureFactory);
        }

        private static X509Extensions GenerateX509Extensions(IList<X509ExtensionEntity> entities)
        {
            if (entities == null)
            {
                throw new ArgumentNullException(nameof(entities));
            }
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            Dictionary<DerObjectIdentifier, X509Extension> attributes = new Dictionary<DerObjectIdentifier, X509Extension>();
            foreach (X509ExtensionEntity entity in entities)
            {
                ordering.Add(entity.Oid);
                attributes.Add(entity.Oid, new X509Extension(entity.IsCritical, new DerOctetString(entity.Value)));
            }
            return new X509Extensions(ordering, attributes);
        }

        private static X509Name GenerateX509Name(IList<X509NameEntity> entities)
        {
            if (entities == null)
            {
                throw new ArgumentNullException(nameof(entities));
            }
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            Dictionary<DerObjectIdentifier, string> attributes = new Dictionary<DerObjectIdentifier, string>();
            foreach (X509NameEntity entity in entities)
            {
                ordering.Add(entity.Oid);
                attributes.Add(entity.Oid, entity.Value);
            }
            return new X509Name(ordering, attributes);
        }
    }
}