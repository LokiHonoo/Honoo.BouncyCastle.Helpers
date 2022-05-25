using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
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
            Demo("SM2", "SHA256withSM2", "SM3withSM2");
            //
            Console.WriteLine("\r\n\r\n\r\n");
        }

        private static void BuildCAUnit(string asymmetricAlgorithm, string signatureAlgorithm, out AsymmetricKeyParameter caPrivateKey, out X509Certificate caCert)
        {
            AsymmetricAlgorithmHelper.TryGetAlgorithm(asymmetricAlgorithm, out IAsymmetricAlgorithm algorithm);
            AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
            caPrivateKey = keyPair.Private;
            Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"TEST Root CA")
            };
            X509Name dn = X509Helper.GenerateX509Name(names);
            Tuple<X509ExtensionLabel, bool, Asn1Encodable>[] exts = new Tuple<X509ExtensionLabel, bool, Asn1Encodable>[]
            {
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions extensions = X509Helper.GenerateX509Extensions(exts);
            caCert = X509Helper.GenerateIssuerCert(signatureAlgorithm,
                                                   keyPair,
                                                   dn,
                                                   extensions,
                                                   DateTime.UtcNow.AddDays(-1),
                                                  TimeSpan.FromDays(120));

            _ = PemHelper.KeyToPem(keyPair.Private, PemHelper.DEKAlgorithmNames.RC2_64_CBC, "abc123");
            _ = PemHelper.KeyToPem(keyPair.Public);
            _ = PemHelper.CertToPem(caCert);
        }

        private static void BuildUserUnit(out AsymmetricKeyParameter userPrivateKey, out Pkcs10CertificationRequest userCsr)
        {
            ISignatureAlgorithm algorithm = SignatureAlgorithmHelper.GOST3411withECGOST3410;
            AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
            userPrivateKey = keyPair.Private;
            Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"TEST User")
            };
            X509Name dn = X509Helper.GenerateX509Name(names);
            Tuple<X509ExtensionLabel, bool, Asn1Encodable>[] exts = new Tuple<X509ExtensionLabel, bool, Asn1Encodable>[]
            {
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions extensions = X509Helper.GenerateX509Extensions(exts);
            userCsr = X509Helper.GenerateCsr(algorithm, keyPair, dn, extensions);
        }

        private static void Demo(string caAsymmetricAlgorithm, string caSignatureAlgorithm, string subjectSignatureAlgorithm)
        {
            //
            // CA build self.
            //
            BuildCAUnit(caAsymmetricAlgorithm, caSignatureAlgorithm, out AsymmetricKeyParameter caPrivateKey, out X509Certificate caCert);
            //
            // User create csr and sand to CA.
            //
            BuildUserUnit(out AsymmetricKeyParameter _, out Pkcs10CertificationRequest userCsr);
            //
            // CA extract csr and create user cert.
            //
            X509Helper.ExtractCsr(userCsr, out AsymmetricKeyParameter userPublicKey, out X509Name userDN, out X509Extensions userExtensions);
            X509Certificate userCert = X509Helper.GenerateSubjectCert(subjectSignatureAlgorithm,
                                                                      caPrivateKey,
                                                                      caCert,
                                                                      userPublicKey,
                                                                      userDN,
                                                                      userExtensions,
                                                                      DateTime.UtcNow.AddDays(-1),
                                                                     TimeSpan.FromDays(90));
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