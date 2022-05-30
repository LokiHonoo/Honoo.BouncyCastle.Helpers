using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {
            string a;

            X509Crl crl = new X509CrlParser().ReadCrl(File.ReadAllBytes("aaa.crl"));
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(crl);
                a = writer.ToString();
            }

            using (StringReader reader = new StringReader(a))
            {
                object obj = new PemReader(reader).ReadObject();
                crl = (X509Crl)obj;
            }

            Console.WriteLine("\r\n\r\n");
        }
    }
}