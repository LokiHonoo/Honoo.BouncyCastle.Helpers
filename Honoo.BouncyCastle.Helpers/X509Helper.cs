using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
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
        public static void ExtractCsr(Pkcs10CertificationRequest csr, out AsymmetricKeyParameter publicKey, out X509Name dn, out X509Extensions extensions)
        {
            if (csr is null)
            {
                throw new ArgumentNullException(nameof(csr));
            }
            publicKey = csr.GetPublicKey();
            CertificationRequestInfo csrInfo = csr.GetCertificationRequestInfo();
            dn = csrInfo.Subject;
            Dictionary<DerObjectIdentifier, X509Extension> attributes = new Dictionary<DerObjectIdentifier, X509Extension>();
            if (csrInfo.Attributes != null)
            {
                foreach (AttributePkcs attribute in csrInfo.Attributes)
                {
                    if (attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
                    {
                        foreach (X509Extensions exts in attribute.AttrValues)
                        {
                            foreach (DerObjectIdentifier oid in exts.ExtensionOids)
                            {
                                X509Extension ext = exts.GetExtension(oid);
                                attributes.Add(oid, new X509Extension(ext.IsCritical, ext.Value));
                            }
                        }
                    }
                }
            }
            extensions = attributes.Count > 0 ? new X509Extensions(attributes) : null;
        }

        /// <summary>
        /// Generate certificate signing request.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm supported by x590.</param>
        /// <param name="keyPair">Asymmetric key pair.</param>
        /// <param name="dn">Distinct name.</param>
        /// <param name="extensions">Extensions.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest GenerateCsr(ISignatureAlgorithm signatureAlgorithm,
                                                             AsymmetricCipherKeyPair keyPair,
                                                             X509Name dn,
                                                             X509Extensions extensions)
        {
            if (signatureAlgorithm is null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (keyPair is null)
            {
                throw new ArgumentNullException(nameof(keyPair));
            }
            if (dn is null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (signatureAlgorithm.Oid is null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                return GenerateCsr(signatureAlgorithm.Oid.Id, keyPair, dn, extensions);
            }
        }

        /// <summary>
        /// Generate certificate signing request.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm mechanism or oid supported by x590.</param>
        /// <param name="keyPair">Asymmetric key pair.</param>
        /// <param name="dn">Distinct name.</param>
        /// <param name="extensions">Extensions.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs10CertificationRequest GenerateCsr(string signatureAlgorithm,
                                                             AsymmetricCipherKeyPair keyPair,
                                                             X509Name dn,
                                                             X509Extensions extensions)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (keyPair is null)
            {
                throw new ArgumentNullException(nameof(keyPair));
            }
            if (dn is null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (SignatureAlgorithmHelper.TryGetOid(signatureAlgorithm, out DerObjectIdentifier oid))
            {
                Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory(oid.Id, keyPair.Private, Common.SecureRandom);
                DerSet attribute = extensions is null ? null : new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions)));
                return new Pkcs10CertificationRequest(signatureFactory, dn, keyPair.Public, attribute);
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
        /// <param name="keyPair">The asymmetric key pair of issuer.</param>
        /// <param name="dn">The distinct name of issuer.</param>
        /// <param name="extensions">Extensions of issuer.</param>
        /// <param name="start">Start time.</param>
        /// <param name="expiration">The expiration times from the start time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateIssuerCert(ISignatureAlgorithm signatureAlgorithm,
                                                         AsymmetricCipherKeyPair keyPair,
                                                         X509Name dn,
                                                         X509Extensions extensions,
                                                         DateTime start,
                                                         TimeSpan expiration)
        {
            if (signatureAlgorithm is null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (keyPair is null)
            {
                throw new ArgumentNullException(nameof(keyPair));
            }
            if (dn is null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (signatureAlgorithm.Oid is null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                return GenerateCert(signatureAlgorithm.Oid.Id, keyPair.Private, dn, keyPair.Public, dn, extensions, start, expiration);
            }
        }

        /// <summary>
        /// Generate issuer self signed certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm mechanism or oid supported by x590.</param>
        /// <param name="keyPair">The asymmetric key pair of issuer.</param>
        /// <param name="dn">The distinct name of issuer.</param>
        /// <param name="extensions">Extensions of issuer.</param>
        /// <param name="start">Start time.</param>
        /// <param name="expiration">The expiration times from the start time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateIssuerCert(string signatureAlgorithm,
                                                         AsymmetricCipherKeyPair keyPair,
                                                         X509Name dn,
                                                         X509Extensions extensions,
                                                         DateTime start,
                                                         TimeSpan expiration)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (keyPair is null)
            {
                throw new ArgumentNullException(nameof(keyPair));
            }
            if (dn is null)
            {
                throw new ArgumentNullException(nameof(dn));
            }
            if (SignatureAlgorithmHelper.TryGetOid(signatureAlgorithm, out DerObjectIdentifier oid))
            {
                return GenerateCert(oid.Id, keyPair.Private, dn, keyPair.Public, dn, extensions, start, expiration);
            }
            else
            {
                throw new ArgumentException("Unsupported signature algorithm.", signatureAlgorithm);
            }
        }

        /// <summary>
        /// Generate Pkcs#12 certificate.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="privateKeyAlias">The alias of private key.</param>
        /// <param name="namedCerts">Certificate collection with alias set.</param>
        /// <param name="password">Password.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static Pkcs12Store GeneratePkcs12(AsymmetricKeyParameter privateKey,
                                                 string privateKeyAlias,
                                                 Dictionary<string, X509Certificate> namedCerts,
                                                 string password)
        {
            if (privateKey is null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (privateKeyAlias is null)
            {
                throw new ArgumentNullException(nameof(privateKeyAlias));
            }
            if (namedCerts is null)
            {
                throw new ArgumentNullException(nameof(namedCerts));
            }
            using (MemoryStream ms = new MemoryStream())
            {
                Pkcs12Store store = new Pkcs12StoreBuilder().Build();
                List<X509CertificateEntry> certEntries = new List<X509CertificateEntry>();
                foreach (KeyValuePair<string, X509Certificate> namedCert in namedCerts)
                {
                    X509CertificateEntry certEntry = new X509CertificateEntry(namedCert.Value);
                    store.SetCertificateEntry(namedCert.Key, certEntry);
                    certEntries.Add(certEntry);
                }
                store.SetKeyEntry(privateKeyAlias, new AsymmetricKeyEntry(privateKey), certEntries.ToArray());
                char[] pass = string.IsNullOrWhiteSpace(password) ? null : password.ToCharArray();
                store.Save(ms, pass, Common.SecureRandom);
                ms.Flush();
                return new Pkcs12Store(ms, pass);
            }
        }

        /// <summary>
        /// Generate subject certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm supported by x590.</param>
        /// <param name="issuerPrivateKey">The asymmetric private key of issuer.</param>
        /// <param name="issuerCert">The certificate of issuer.</param>
        /// <param name="subjectPublicKey">The asymmetric public key of subject.</param>
        /// <param name="subjectDN">The distinct name of subject.</param>
        /// <param name="subjectExtensions">Extensions of subject.</param>
        /// <param name="start">Start time.</param>
        /// <param name="expiration">The expiration times from the start time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateSubjectCert(ISignatureAlgorithm signatureAlgorithm,
                                                          AsymmetricKeyParameter issuerPrivateKey,
                                                          X509Certificate issuerCert,
                                                          AsymmetricKeyParameter subjectPublicKey,
                                                          X509Name subjectDN,
                                                          X509Extensions subjectExtensions,
                                                          DateTime start,
                                                          TimeSpan expiration)
        {
            if (signatureAlgorithm is null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (issuerPrivateKey is null)
            {
                throw new ArgumentNullException(nameof(issuerPrivateKey));
            }
            if (issuerCert is null)
            {
                throw new ArgumentNullException(nameof(issuerCert));
            }
            if (subjectPublicKey is null)
            {
                throw new ArgumentNullException(nameof(subjectPublicKey));
            }
            try
            {
                issuerCert.CheckValidity();
            }
            catch
            {
                throw new CryptographicException("The issuer's certificate has expired.");
            }
            try
            {
                issuerCert.CheckValidity(start.Add(expiration));
            }
            catch
            {
                throw new CryptographicException("The end time exceeds the validity of the issuer certificate.");
            }
            if (signatureAlgorithm.Oid is null)
            {
                throw new ArgumentException("Unsupported signature algorithm.", nameof(signatureAlgorithm));
            }
            else
            {
                return GenerateCert(signatureAlgorithm.Oid.Id, issuerPrivateKey, issuerCert.SubjectDN, subjectPublicKey, subjectDN, subjectExtensions, start, expiration);
            }
        }

        /// <summary>
        /// Generate subject certificate.
        /// </summary>
        /// <param name="signatureAlgorithm">Signature algorithm mechanism or oid supported by x590.</param>
        /// <param name="issuerPrivateKey">The asymmetric private key of issuer.</param>
        /// <param name="issuerCert">The certificate of issuer.</param>
        /// <param name="subjectPublicKey">The asymmetric public key of subject.</param>
        /// <param name="subjectDN">The distinct name of subject.</param>
        /// <param name="subjectExtensions">Extensions of subject.</param>
        /// <param name="start">Start time.</param>
        /// <param name="expiration">The expiration times from the start time.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Certificate GenerateSubjectCert(string signatureAlgorithm,
                                                          AsymmetricKeyParameter issuerPrivateKey,
                                                          X509Certificate issuerCert,
                                                          AsymmetricKeyParameter subjectPublicKey,
                                                          X509Name subjectDN,
                                                          X509Extensions subjectExtensions,
                                                          DateTime start,
                                                          TimeSpan expiration)
        {
            if (string.IsNullOrWhiteSpace(signatureAlgorithm))
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }
            if (issuerPrivateKey is null)
            {
                throw new ArgumentNullException(nameof(issuerPrivateKey));
            }
            if (issuerCert is null)
            {
                throw new ArgumentNullException(nameof(issuerCert));
            }
            if (subjectPublicKey is null)
            {
                throw new ArgumentNullException(nameof(subjectPublicKey));
            }
            try
            {
                issuerCert.CheckValidity();
            }
            catch
            {
                throw new CryptographicException("The issuer's certificate has expired.");
            }
            try
            {
                issuerCert.CheckValidity(start.Add(expiration));
            }
            catch
            {
                throw new CryptographicException("The end time exceeds the validity of the issuer certificate.");
            }
            if (SignatureAlgorithmHelper.TryGetOid(signatureAlgorithm, out DerObjectIdentifier oid))
            {
                return GenerateCert(oid.Id, issuerPrivateKey, issuerCert.SubjectDN, subjectPublicKey, subjectDN, subjectExtensions, start, expiration);
            }
            else
            {
                throw new ArgumentException("Unsupported signature algorithm.", signatureAlgorithm);
            }
        }

        /// <summary>
        /// Generate x509 extensions.
        /// <para/>Example: var extension1 = new Tuple&lt;X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false));
        /// <para/>Example: var extension1 = new Tuple&lt;X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        /// </summary>
        /// <param name="extensions">X509 extension collection.</param>
        /// <returns></returns>
        public static X509Extensions GenerateX509Extensions(IEnumerable<Tuple<X509ExtensionLabel, bool, Asn1Encodable>> extensions)
        {
            if (extensions is null)
            {
                throw new ArgumentNullException(nameof(extensions));
            }
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            Dictionary<DerObjectIdentifier, X509Extension> attributes = new Dictionary<DerObjectIdentifier, X509Extension>();
            IEnumerator<Tuple<X509ExtensionLabel, bool, Asn1Encodable>> enumerator = extensions.GetEnumerator();
            while (enumerator.MoveNext())
            {
                DerObjectIdentifier oid = GetX509ExtensionOid(enumerator.Current.Item1);
                ordering.Add(oid);
                attributes.Add(oid, new X509Extension(enumerator.Current.Item2, new DerOctetString(enumerator.Current.Item3)));
            }
            return new X509Extensions(ordering, attributes);
        }

        /// <summary>
        /// Generate x509 extensions.
        /// <para/>Example: var extension1 = new Tuple&lt;DerObjectIdentifier, bool, Asn1Encodable>(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        /// <para/>Example: var extension1 = new Tuple&lt;DerObjectIdentifier, bool, Asn1Encodable>(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        /// </summary>
        /// <param name="extensions">X509 extension collection.</param>
        /// <returns></returns>
        public static X509Extensions GenerateX509Extensions(IEnumerable<Tuple<DerObjectIdentifier, bool, Asn1Encodable>> extensions)
        {
            if (extensions is null)
            {
                throw new ArgumentNullException(nameof(extensions));
            }
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            Dictionary<DerObjectIdentifier, X509Extension> attributes = new Dictionary<DerObjectIdentifier, X509Extension>();
            IEnumerator<Tuple<DerObjectIdentifier, bool, Asn1Encodable>> enumerator = extensions.GetEnumerator();
            while (enumerator.MoveNext())
            {
                ordering.Add(enumerator.Current.Item1);
                attributes.Add(enumerator.Current.Item1, new X509Extension(enumerator.Current.Item2, new DerOctetString(enumerator.Current.Item3)));
            }
            return new X509Extensions(ordering, attributes);
        }

        /// <summary>
        /// Generate x509 name.
        /// <para/>Example: var name = new Tuple&lt;X509NameLabel, string>(X509NameLabel.CN, "Demo Cert");
        /// </summary>
        /// <param name="names">X509 name collection.</param>
        /// <returns></returns>
        public static X509Name GenerateX509Name(IEnumerable<Tuple<X509NameLabel, string>> names)
        {
            if (names is null)
            {
                throw new ArgumentNullException(nameof(names));
            }
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            Dictionary<DerObjectIdentifier, string> attributes = new Dictionary<DerObjectIdentifier, string>();
            IEnumerator<Tuple<X509NameLabel, string>> enumerator = names.GetEnumerator();
            while (enumerator.MoveNext())
            {
                DerObjectIdentifier oid = GetX509NameOid(enumerator.Current.Item1);
                ordering.Add(oid);
                attributes.Add(oid, enumerator.Current.Item2);
            }
            return new X509Name(ordering, attributes);
        }

        /// <summary>
        /// Generate x509 name.
        /// <para/>Example: var name = new Tuple&lt;DerObjectIdentifier, string>(X509Name.CN, "Demo Cert");
        /// </summary>
        /// <param name="names">X509 name collection.</param>
        /// <returns></returns>
        public static X509Name GenerateX509Name(IEnumerable<Tuple<DerObjectIdentifier, string>> names)
        {
            if (names is null)
            {
                throw new ArgumentNullException(nameof(names));
            }
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            Dictionary<DerObjectIdentifier, string> attributes = new Dictionary<DerObjectIdentifier, string>();
            IEnumerator<Tuple<DerObjectIdentifier, string>> enumerator = names.GetEnumerator();
            while (enumerator.MoveNext())
            {
                ordering.Add(enumerator.Current.Item1);
                attributes.Add(enumerator.Current.Item1, enumerator.Current.Item2);
            }
            return new X509Name(ordering, attributes);
        }

        private static X509Certificate GenerateCert(string signatureAlgorithmOid,
                                                    AsymmetricKeyParameter issuerPrivateKey,
                                                    X509Name issuerDN,
                                                    AsymmetricKeyParameter subjectPublicKey,
                                                    X509Name subjectDN,
                                                    X509Extensions subjectExtensions,
                                                    DateTime start,
                                                    TimeSpan expiration)
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
                foreach (DerObjectIdentifier oid in subjectExtensions.ExtensionOids)
                {
                    X509Extension extension = subjectExtensions.GetExtension(oid);
                    generator.AddExtension(oid, extension.IsCritical, extension.GetParsedValue());
                }
            }
            generator.SetNotBefore(start);
            generator.SetNotAfter(start.Add(expiration));
            return generator.Generate(signatureFactory);
        }

        private static DerObjectIdentifier GetX509ExtensionOid(X509ExtensionLabel label)
        {
            switch (label)
            {
                case X509ExtensionLabel.AuditIdentity: return X509Extensions.AuditIdentity;
                case X509ExtensionLabel.AuthorityInfoAccess: return X509Extensions.AuthorityInfoAccess;
                case X509ExtensionLabel.AuthorityKeyIdentifier: return X509Extensions.AuthorityKeyIdentifier;
                case X509ExtensionLabel.BasicConstraints: return X509Extensions.BasicConstraints;
                case X509ExtensionLabel.BiometricInfo: return X509Extensions.BiometricInfo;
                case X509ExtensionLabel.CertificateIssuer: return X509Extensions.CertificateIssuer;
                case X509ExtensionLabel.CertificatePolicies: return X509Extensions.CertificatePolicies;
                case X509ExtensionLabel.CrlDistributionPoints: return X509Extensions.CrlDistributionPoints;
                case X509ExtensionLabel.CrlNumber: return X509Extensions.CrlNumber;
                case X509ExtensionLabel.DeltaCrlIndicator: return X509Extensions.DeltaCrlIndicator;
                case X509ExtensionLabel.ExpiredCertsOnCrl: return X509Extensions.ExpiredCertsOnCrl;
                case X509ExtensionLabel.ExtendedKeyUsage: return X509Extensions.ExtendedKeyUsage;
                case X509ExtensionLabel.FreshestCrl: return X509Extensions.FreshestCrl;
                case X509ExtensionLabel.InhibitAnyPolicy: return X509Extensions.InhibitAnyPolicy;
                case X509ExtensionLabel.InstructionCode: return X509Extensions.InstructionCode;
                case X509ExtensionLabel.InvalidityDate: return X509Extensions.InvalidityDate;
                case X509ExtensionLabel.IssuerAlternativeName: return X509Extensions.IssuerAlternativeName;
                case X509ExtensionLabel.IssuingDistributionPoint: return X509Extensions.IssuingDistributionPoint;
                case X509ExtensionLabel.KeyUsage: return X509Extensions.KeyUsage;
                case X509ExtensionLabel.LogoType: return X509Extensions.LogoType;
                case X509ExtensionLabel.NameConstraints: return X509Extensions.NameConstraints;
                case X509ExtensionLabel.NoRevAvail: return X509Extensions.NoRevAvail;
                case X509ExtensionLabel.PolicyConstraints: return X509Extensions.PolicyConstraints;
                case X509ExtensionLabel.PolicyMappings: return X509Extensions.PolicyMappings;
                case X509ExtensionLabel.PrivateKeyUsagePeriod: return X509Extensions.PrivateKeyUsagePeriod;
                case X509ExtensionLabel.QCStatements: return X509Extensions.QCStatements;
                case X509ExtensionLabel.ReasonCode: return X509Extensions.ReasonCode;
                case X509ExtensionLabel.SubjectAlternativeName: return X509Extensions.SubjectAlternativeName;
                case X509ExtensionLabel.SubjectDirectoryAttributes: return X509Extensions.SubjectDirectoryAttributes;
                case X509ExtensionLabel.SubjectInfoAccess: return X509Extensions.SubjectInfoAccess;
                case X509ExtensionLabel.SubjectKeyIdentifier: return X509Extensions.SubjectKeyIdentifier;
                case X509ExtensionLabel.TargetInformation: return X509Extensions.TargetInformation;
                default: throw new CryptographicException("Unsupported X509Extension.");
            }
        }

        private static DerObjectIdentifier GetX509NameOid(X509NameLabel label)
        {
            switch (label)
            {
                case X509NameLabel.BusinessCategory: return X509Name.BusinessCategory;
                case X509NameLabel.C: return X509Name.C;
                case X509NameLabel.CN: return X509Name.CN;
                case X509NameLabel.CountryOfCitizenship: return X509Name.CountryOfCitizenship;
                case X509NameLabel.CountryOfResidence: return X509Name.CountryOfResidence;
                case X509NameLabel.DateOfBirth: return X509Name.DateOfBirth;
                case X509NameLabel.DC: return X509Name.DC;
                case X509NameLabel.DmdName: return X509Name.DmdName;
                case X509NameLabel.DnQualifier: return X509Name.DnQualifier;
                case X509NameLabel.E: return X509Name.E;
                case X509NameLabel.EmailAddress: return X509Name.EmailAddress;
                case X509NameLabel.Gender: return X509Name.Gender;
                case X509NameLabel.Generation: return X509Name.Generation;
                case X509NameLabel.GivenName: return X509Name.GivenName;
                case X509NameLabel.Initials: return X509Name.Initials;
                case X509NameLabel.L: return X509Name.L;
                case X509NameLabel.Name: return X509Name.Name;
                case X509NameLabel.NameAtBirth: return X509Name.NameAtBirth;
                case X509NameLabel.O: return X509Name.O;
                case X509NameLabel.OrganizationIdentifier: return X509Name.OrganizationIdentifier;
                case X509NameLabel.OU: return X509Name.OU;
                case X509NameLabel.PlaceOfBirth: return X509Name.PlaceOfBirth;
                case X509NameLabel.PostalAddress: return X509Name.PostalAddress;
                case X509NameLabel.PostalCode: return X509Name.PostalCode;
                case X509NameLabel.Pseudonym: return X509Name.Pseudonym;
                case X509NameLabel.SerialNumber: return X509Name.SerialNumber;
                case X509NameLabel.ST: return X509Name.ST;
                case X509NameLabel.Street: return X509Name.Street;
                case X509NameLabel.Surname: return X509Name.Surname;
                case X509NameLabel.T: return X509Name.T;
                case X509NameLabel.TelephoneNumber: return X509Name.TelephoneNumber;
                case X509NameLabel.UID: return X509Name.UID;
                case X509NameLabel.UniqueIdentifier: return X509Name.UniqueIdentifier;
                case X509NameLabel.UnstructuredAddress: return X509Name.UnstructuredAddress;
                case X509NameLabel.UnstructuredName: return X509Name.UnstructuredName;
                default: throw new CryptographicException("Unsupported X509Name.");
            }
        }
    }
}