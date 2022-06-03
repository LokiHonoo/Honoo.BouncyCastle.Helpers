using Honoo.BouncyCastle.Helpers;
using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {SymmetricCipherMode2.
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            foreach (var item in generator.SignatureAlgNames)
            {
                Console.WriteLine(item);
            }
            ;
            //
            //
            //
            Console.WriteLine("\r\n\r\n");
        }
    }
}