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

        private static void BuildCAUnit(out AsymmetricKeyParameter caPrivateKey, out X509Certificate caCert)
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.ECDSA.GenerateKeyPair();
            caPrivateKey = keyPair.Private;
            Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"Honoo.Net.Sockets TEST Root CA")
            };
            X509Name dn = X509Helper.GenerateX509Name(names);
            Tuple<X509ExtensionLabel, bool, Asn1Encodable>[] exts = new Tuple<X509ExtensionLabel, bool, Asn1Encodable>[]
            {
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions extensions = X509Helper.GenerateX509Extensions(exts);
            caCert = X509Helper.GenerateIssuerCert("SHA224withECDSA",
                                                   keyPair,
                                                   dn,
                                                   extensions,
                                                   DateTime.UtcNow.AddDays(-1),
                                                   365);

            _ = PemHelper.KeyToPem(keyPair.Private, PemHelper.DEKAlgorithmNames.RC2_64_CBC, "abc123");
            _ = PemHelper.KeyToPem(keyPair.Public);
            _ = PemHelper.CertToPem(caCert);
        }

        private static void BuildClientUnit(out Pkcs10CertificationRequest clientCsr)
        {
            ISignatureAlgorithm algorithm = SignatureAlgorithmHelper.GOST3411withECGOST3410;
            AsymmetricCipherKeyPair keyPair = algorithm.AsymmetricAlgorithm.GenerateKeyPair();
            Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"Honoo.Net.Sockets TEST TCP Client")
            };
            X509Name dn = X509Helper.GenerateX509Name(names);
            Tuple<X509ExtensionLabel, bool, Asn1Encodable>[] exts = new Tuple<X509ExtensionLabel, bool, Asn1Encodable>[]
            {
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions extensions = X509Helper.GenerateX509Extensions(exts);
            clientCsr = X509Helper.GenerateCsr(algorithm, keyPair, dn, extensions);
        }

        private static void BuildServerUnit(out Pkcs10CertificationRequest serverCsr)
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.ECGOST3410.GenerateKeyPair();
            Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
            {
                new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
                new Tuple<X509NameLabel, string>(X509NameLabel.CN,"Honoo.Net.Sockets TEST TCP Server")
            };
            X509Name dn = X509Helper.GenerateX509Name(names);
            Tuple<X509ExtensionLabel, bool, Asn1Encodable>[] exts = new Tuple<X509ExtensionLabel, bool, Asn1Encodable>[]
            {
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
                new Tuple<X509ExtensionLabel, bool, Asn1Encodable>(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
            };
            X509Extensions extensions = X509Helper.GenerateX509Extensions(exts);
            serverCsr = X509Helper.GenerateCsr("GOST3411withECGOST3410", keyPair, dn, extensions);
        }

        private static void Demo()
        {
            //
            // CA work
            //
            BuildCAUnit(out AsymmetricKeyParameter caPrivateKey, out X509Certificate caCert);
            //
            // Subject work
            //
            BuildServerUnit(out Pkcs10CertificationRequest serverCsr);
            BuildClientUnit(out Pkcs10CertificationRequest clientCsr);
            //
            // CA work
            //
            X509Helper.ExtractCsr(serverCsr, out AsymmetricKeyParameter serverPublicKey, out X509Name serverDN, out X509Extensions serverExtensions);
            X509Certificate serverCert = X509Helper.GenerateSubjectCert("SHA256WithECDSA",
                                                                        caPrivateKey,
                                                                        caCert,
                                                                        serverPublicKey,
                                                                        serverDN,
                                                                        serverExtensions,
                                                                        DateTime.UtcNow.AddDays(-1),
                                                                        90);
            X509Helper.ExtractCsr(clientCsr, out AsymmetricKeyParameter clientPublicKey, out X509Name clientDN, out X509Extensions clientExtensions);
            //
            SignatureAlgorithmHelper.TryGetAlgorithm("SHA256WithECDSA", out ISignatureAlgorithm signatureAlgorithm);
            X509Certificate clientCert = X509Helper.GenerateSubjectCert(signatureAlgorithm,
                                                                        caPrivateKey,
                                                                        caCert,
                                                                        clientPublicKey,
                                                                        clientDN,
                                                                        clientExtensions,
                                                                        DateTime.UtcNow.AddDays(-1),
                                                                        90);
            //
            //
            // Print
            //
            Console.WriteLine("====  CA Cert  =====================================================================================");
            Console.WriteLine(caCert.ToString());
            Console.WriteLine("====  Server Cert  =================================================================================");
            Console.WriteLine(serverCert.ToString());
            Console.WriteLine("====  Client Cert  =================================================================================");
            Console.WriteLine(clientCert.ToString());
            Console.WriteLine();
            //
            // Verify
            //
            bool validated;
            try
            {
                serverCert.Verify(caCert.GetPublicKey());
                validated = true;
            }
            catch
            {
                validated = false;
            }
            Console.WriteLine("Verify server cert - " + validated);
            try
            {
                clientCert.Verify(caCert.GetPublicKey());
                validated = true;
            }
            catch
            {
                validated = false;
            }
            Console.WriteLine("Verify client cert - " + validated);
        }
    }
}