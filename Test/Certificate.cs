using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;

namespace Test
{
    internal static class Certificate
    {
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

        private static void Demo()
        {
            string caSignatureAlgorithmName = "SHA512withECDSA";
            string userSignatureAlgorithmName = "SHA256withECDSA";
            //
            // CA build self.
            //
            _ = SignatureAlgorithmHelper.TryGetAlgorithm(caSignatureAlgorithmName, out ISignatureAlgorithm caSignatureAlgorithm);
            AsymmetricCipherKeyPair caKeyPair = caSignatureAlgorithm.GenerateKeyPair();
            //
            X509NameEntity[] x509NameEntities = new X509NameEntity[]
            {
                new X509NameEntity(X509NameLabel.C,"CN"),
                new X509NameEntity(X509NameLabel.CN,"TEST Root CA")
            };
            X509Name caDN = X509Helper.GenerateX509Name(x509NameEntities);
            X509ExtensionEntity[] x509ExtensionEntities = new X509ExtensionEntity[]
            {
                new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions caExtensions = X509Helper.GenerateX509Extensions(x509ExtensionEntities);
            X509Certificate caCert = X509Helper.GenerateIssuerCert(caSignatureAlgorithm,
                                                                   caKeyPair,
                                                                   caDN,
                                                                   caExtensions,
                                                                   DateTime.UtcNow.AddDays(-3),
                                                                   DateTime.UtcNow.AddDays(120));
            X509RevocationEntity[] revocationEntities = new X509RevocationEntity[]
            {
                new X509RevocationEntity(new BigInteger("1234567890"), DateTime.UtcNow, null)
            };

            X509Crl crl = X509Helper.GenerateCrl(caSignatureAlgorithm,
                                                 caKeyPair.Private,
                                                 caCert,
                                                 revocationEntities,
                                                 null,
                                                 DateTime.UtcNow.AddDays(-2),
                                                 DateTime.UtcNow.AddDays(30));
            //
            // User create csr and sand to CA.
            //
            AsymmetricCipherKeyPair userKeyPair = SignatureAlgorithmHelper.GOST3411withECGOST3410.GenerateKeyPair();
            X509NameEntity[] x509NameEntities2 = new X509NameEntity[]
            {
                new X509NameEntity(X509NameLabel.C,"CN"),
                new X509NameEntity(X509NameLabel.CN,"TEST User")
            };
            X509Name userDN = X509Helper.GenerateX509Name(x509NameEntities2);
            X509Extensions userExtensions = null;
            Pkcs10CertificationRequest userCsr = X509Helper.GenerateCsr(SignatureAlgorithmHelper.GOST3411withECGOST3410, userKeyPair, userDN, userExtensions);
            //
            // CA extract csr and create user cert.
            //
            X509Helper.ExtractCsr(userCsr, out AsymmetricKeyParameter userPublicKey, out X509Name userDNExtracted, out X509Extensions userExtensionsExtracted);
            X509Certificate userCert = X509Helper.GenerateSubjectCert(userSignatureAlgorithmName,
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
            Console.WriteLine("====  CA Cert  =====================================================================================");
            Console.WriteLine(caCert.ToString());
            Console.WriteLine("====  User Cert  =================================================================================");
            Console.WriteLine(userCert.ToString());
            Console.WriteLine();
            //
            // User verify cert.
            //
            bool validated;
            try
            {
                crl.Verify(caCert.GetPublicKey());
                userCert.Verify(caCert.GetPublicKey());
                validated = true;
            }
            catch
            {
                validated = false;
            }
            Console.WriteLine("Verify user cert - " + validated);
        }
    }
}