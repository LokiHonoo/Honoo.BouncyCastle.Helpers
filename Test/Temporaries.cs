using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {
            AsymmetricCipherKeyPair keyPair = SignatureAlgorithms.SHA256withECDSA.AsymmetricAlgorithm.GenerateKeyPair();
            X509NameEntity[] dn = new X509NameEntity[]
{
                new X509NameEntity(X509NameLabel.C,"CN"),
                new X509NameEntity(X509NameLabel.CN,"TEST Root CA")
};
            X509Certificate cert = X509Helper.GenerateIssuerCertificate("SHA512withECDSA",
                                                                   keyPair,
                                                                   dn,
                                                                   null,
                                                                   DateTime.UtcNow.AddDays(-3),
                                                                   DateTime.UtcNow.AddDays(120));
            using (Stream ms = new MemoryStream())
            {
                X509Helper.GeneratePkcs12(ms, "key", keyPair.Private, new X509Certificate[] { cert }, string.Empty, null, string.Empty);
                ms.Seek(0, SeekOrigin.Begin);
                Pkcs12Store store = X509Helper.ReadPkcs12(ms, string.Empty);
            }

            //
            //
            //
            Console.WriteLine("\r\n\r\n");
        }
    }
}