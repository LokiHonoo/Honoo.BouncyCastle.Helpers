using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Test
{
    internal struct PemTestObject
    {
        internal X509Crl Crl { get; set; }
        internal X509Certificate Cert { get; set; }
        internal Pkcs10CertificationRequest Csr { get; set; }
        internal AsymmetricCipherKeyPair KeyPair { get; set; }
    }
}