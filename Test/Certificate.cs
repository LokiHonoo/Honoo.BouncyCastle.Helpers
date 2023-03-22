using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace Test
{
    internal static class Certificate
    {
        internal static PemTestObject Demo()
        {
            //
            // CA build self.
            //
            _ = SignatureAlgorithmHelper.TryGetAlgorithm("SHA512withECDSA", out ISignatureAlgorithm caSignatureAlgorithm);
            AsymmetricCipherKeyPair caKeyPair = caSignatureAlgorithm.AsymmetricAlgorithm.GenerateKeyPair();
            //
            X509NameEntity[] caDN = new X509NameEntity[]
            {
                new X509NameEntity(X509NameLabel.C,"CN"),
                new X509NameEntity(X509NameLabel.CN,"TEST Root CA")
            };
            X509ExtensionEntity[] caExtensions = new X509ExtensionEntity[]
            {
                new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Certificate caCert = X509Helper.GenerateIssuerCertificate(caSignatureAlgorithm,
                                                                          caKeyPair,
                                                                          caDN,
                                                                          caExtensions,
                                                                          DateTime.UtcNow.AddDays(-3),
                                                                          DateTime.UtcNow.AddDays(120));
            X509RevocationEntity[] revocationEntities = new X509RevocationEntity[]
            {
                new X509RevocationEntity(new BigInteger("12345678901"), DateTime.UtcNow.AddDays(-2), null),
                new X509RevocationEntity(new BigInteger("12345678902"), DateTime.UtcNow.AddDays(-2), null)
            };

            X509Crl caCrl = X509Helper.GenerateCrl(caSignatureAlgorithm,
                                                   caKeyPair.Private,
                                                   caCert,
                                                   revocationEntities,
                                                   null,
                                                   DateTime.UtcNow.AddDays(-2),
                                                   DateTime.UtcNow.AddDays(30));
            //
            // User create csr and sand to CA.
            //
            AsymmetricCipherKeyPair userKeyPair = SignatureAlgorithms.GOST3411withECGOST3410.AsymmetricAlgorithm.GenerateKeyPair();
            X509NameEntity[] userDN = new X509NameEntity[]
            {
                new X509NameEntity(X509NameLabel.C,"CN"),
                new X509NameEntity(X509NameLabel.CN,"TEST User")
            };
            X509ExtensionEntity[] userExtensions = new X509ExtensionEntity[]
            {
                new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            Pkcs10CertificationRequest userCsr = X509Helper.GenerateCsr(SignatureAlgorithms.GOST3411withECGOST3410, userKeyPair, userDN, userExtensions);
            //
            // CA extract csr and create user cert.
            //
            X509Helper.ExtractCsr(userCsr,
                                  out AsymmetricKeyParameter userPublicKey,
                                  out IList<X509NameEntity> userDNExtracted,
                                  out IList<X509ExtensionEntity> userExtensionsExtracted);
            X509Certificate userCert = X509Helper.GenerateSubjectCertificate("SHA256withECDSA",
                                                                             caKeyPair.Private,
                                                                             caCert,
                                                                             userPublicKey,
                                                                             userDNExtracted,
                                                                             userExtensionsExtracted,
                                                                             DateTime.UtcNow.AddDays(-1),
                                                                             DateTime.UtcNow.AddDays(90));
            //
            //
            // Print
            //
            Console.WriteLine("====  CA Cert  ===========================");
            Console.WriteLine(caCert.ToString());
            Console.WriteLine("====  CA Crl  ============================");
            Console.WriteLine(caCrl.ToString());
            Console.WriteLine("====  User Cert  =========================");
            Console.WriteLine(userCert.ToString());
            Console.WriteLine();
            //
            // User verify cert.
            //
            bool validated;
            try
            {
                caCrl.Verify(caCert.GetPublicKey());
                userCert.Verify(caCert.GetPublicKey());
                validated = true;
            }
            catch
            {
                validated = false;
            }
            Console.WriteLine("Verify user cert - " + validated);

            PemTestObject obj = new PemTestObject();
            obj.KeyPair = caKeyPair;
            obj.Cert = caCert;
            obj.Crl = caCrl;
            obj.Csr = userCsr;
            return obj;
        }

        internal static void Test()
        {
            Console.WriteLine();
            Console.WriteLine("====  Certificate Test  ================================================================================================");
            Console.WriteLine();
            //
            Demo();
            //
            Console.WriteLine("\r\n\r\n\r\n");
        }
    }
}