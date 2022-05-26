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
            Tuple<X509NameLabel, string>[] caDNEntitys = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"TEST Root CA")
            };
            X509Name caDN = X509Helper.GenerateX509Name(caDNEntitys);
            Tuple<X509ExtensionLabel, bool, Asn1Encodable>[] caExtensionEntitys = new Tuple<X509ExtensionLabel, bool, Asn1Encodable>[]
            {
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions caExtensions = X509Helper.GenerateX509Extensions(caExtensionEntitys);
            X509Certificate caCert = X509Helper.GenerateIssuerCert(caSignatureAlgorithm,
                                                                   caKeyPair,
                                                                   caDN,
                                                                   caExtensions,
                                                                   DateTime.UtcNow.AddDays(-1),
                                                                   TimeSpan.FromDays(120));

            _ = PemHelper.KeyToPem(caKeyPair.Private, PemHelper.DEKAlgorithmNames.RC2_64_CBC, "abc123");
            _ = PemHelper.KeyToPem(caKeyPair.Public);
            _ = PemHelper.CertToPem(caCert);
            //
            // User create csr and sand to CA.
            //
            AsymmetricCipherKeyPair userKeyPair = SignatureAlgorithmHelper.GOST3411withECGOST3410.GenerateKeyPair();
            Tuple<X509NameLabel, string>[] userDNEntitys = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"TEST User")
            };
            X509Name userDN = X509Helper.GenerateX509Name(userDNEntitys);
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