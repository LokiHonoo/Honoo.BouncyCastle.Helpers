# Honoo.BouncyCastle.Helpers

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Honoo.BouncyCastle.Helpers](#honoobouncycastlehelpers)
  - [Introduction](#introduction)
  - [Quick-Start](#quick-start)
    - [NuGet](#nuget)
    - [Namespace](#namespace)
    - [Hash](#hash)
    - [HMAC](#hmac)
    - [CMAC](#cmac)
    - [MAC](#mac)
    - [Symmetric encryption](#symmetric-encryption)
    - [Asymmetric encryption](#asymmetric-encryption)
    - [Signature](#signature)
    - [Certificate](#certificate)
  - [BUG](#bug)
  - [License](#license)

<!-- /code_chunk_output -->

## Introduction

BouncyCastle's Helpers.

## Quick-Start

### NuGet

<https://www.nuget.org/packages/Honoo.BouncyCastle.Helpers/>

### Namespace

```c#

using Org.BouncyCastle.Crypto;
using Honoo.BouncyCastle.Helpers;

```

### Hash

```c#

private static void Demo1()
{
    byte[] test = Utilities.ScoopBytes(123);
    IDigest digest = HashAlgorithmHelper.SHA3_256.GenerateDigest();
    byte[] hash = new byte[digest.GetDigestSize()];
    //byte[] hash = new byte[HashAlgorithmHelper.SHA3_256.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash, 0);
}

```

### HMAC

```c#

private static void Demo2()
{
    byte[] test = Utilities.ScoopBytes(123);
    byte[] key = Utilities.ScoopBytes(72);
    ICipherParameters parameters = HMACHelper.SHA3_256_HMAC.GenerateParameters(key);
    IMac digest = HMACHelper.SHA3_256_HMAC.GenerateDigest(parameters);
    byte[] hash = new byte[digest.GetMacSize()];
    //byte[] hash = new byte[HMACHelper.SHA3_256_HMAC.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash, 0);
}

```

### CMAC

```c#

private static void Demo3()
{
    byte[] test = Utilities.ScoopBytes(123);
    byte[] key = Utilities.ScoopBytes(128 / 8);
    ICipherParameters parameters = CMACHelper.AES_CMAC.GenerateParameters(key);
    IMac digest = CMACHelper.AES_CMAC.GenerateDigest(parameters);
    byte[] hash = new byte[digest.GetMacSize()];
    //byte[] hash = new byte[CMACHelper.AES_CMAC.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash, 0);
}

```

### MAC

```c#

private static void Demo4()
{
    byte[] test = Utilities.ScoopBytes(123);
    byte[] key = Utilities.ScoopBytes(128 / 8);
    byte[] iv = Utilities.ScoopBytes(128 / 8);
    ICipherParameters parameters = MACHelper.AES_MAC.GenerateParameters(key, iv);
    IMac digest = MACHelper.AES_MAC.GenerateDigest(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters);
    byte[] hash = new byte[digest.GetMacSize()];
    //byte[] hash = new byte[MACHelper.AES_MAC.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash, 0);
}

```

### Symmetric encryption

```c#

private static void Demo1()
{
    byte[] test = Utilities.ScoopBytes(123);
    byte[] key = Utilities.ScoopBytes(128 / 8);
    byte[] iv = Utilities.ScoopBytes(128 / 8);
    ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, iv);
    IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(true, SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(false, SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
    byte[] enc = encryptor.DoFinal(test, 0, test.Length);
    _ = decryptor.DoFinal(enc, 0, enc.Length);
}

private static void Demo2()
{
    byte[] test = Utilities.ScoopBytes(123);
    byte[] key = Utilities.ScoopBytes(128 / 8);
    byte[] nonce = Utilities.ScoopBytes(104 / 8);
    int macSize = 96;
    ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, nonce, macSize, null);
    IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(true, SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(false, SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters);
    byte[] enc = encryptor.DoFinal(test, 0, test.Length);
    _ = decryptor.DoFinal(enc, 0, enc.Length);
}

private static void Demo3()
{
    byte[] test = Utilities.ScoopBytes(123);
    byte[] key = Utilities.ScoopBytes(128 / 8);
    byte[] iv = Utilities.ScoopBytes(128 / 8);
    ICipherParameters parameters = SymmetricAlgorithmHelper.HC128.GenerateParameters(key, iv);
    IBufferedCipher encryptor = SymmetricAlgorithmHelper.HC128.GenerateCipher(true, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithmHelper.HC128.GenerateCipher(false, parameters);
    byte[] enc = encryptor.DoFinal(test, 0, test.Length);
    _ = decryptor.DoFinal(enc, 0, enc.Length);
}

```

### Asymmetric encryption

```c#

private static void Demo1()
{
    byte[] test = Utilities.ScoopBytes(4);
    AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
    IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateCipher(AsymmetricPaddingMode.PKCS1, keyPair.Public);
    IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateCipher(AsymmetricPaddingMode.PKCS1, keyPair.Private);
    byte[] enc = encryptor.ProcessBlock(test, 0, test.Length);
    _ = decryptor.ProcessBlock(enc, 0, enc.Length);
}

```

### Signature

```c#

private static void Demo1()
{
    byte[] test = Utilities.ScoopBytes(93);
    //AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.ECDSA.GenerateKeyPair();
    AsymmetricCipherKeyPair keyPair = SignatureAlgorithmHelper.SHA256withECDSA.AsymmetricAlgorithm.GenerateKeyPair();
    ISigner signer = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner(keyPair.Private);
    ISigner verifier = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner(keyPair.Public);
    signer.BlockUpdate(test, 0, test.Length);
    byte[] signature = signer.GenerateSignature();
    verifier.BlockUpdate(test, 0, test.Length);
    bool same = verifier.VerifySignature(signature);
}

```

### Certificate

```c#

private static void BuildCAUnit(out AsymmetricKeyParameter caPrivateKey, out X509Certificate caCert)
{
    AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.ECDSA.GenerateKeyPair();
    caPrivateKey = keyPair.Private;
    Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
    {
        new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
        new Tuple<X509NameLabel, string>(X509NameLabel.CN,"Sockets TEST Root CA")
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

```

```c#

private static void BuildClientUnit(out Pkcs10CertificationRequest clientCsr)
{
    ISignatureAlgorithm algorithm = SignatureAlgorithmHelper.GOST3411withECGOST3410;
    AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
    Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
    {
        new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
        new Tuple<X509NameLabel, string>(X509NameLabel.CN,"Sockets TEST TCP Client")
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

```

```c#

private static void BuildServerUnit(out Pkcs10CertificationRequest serverCsr)
{
    AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.ECGOST3410.GenerateKeyPair();
    Tuple<X509NameLabel, string>[] names = new Tuple<X509NameLabel, string>[]
    {
        new Tuple<X509NameLabel, string>(X509NameLabel.C,"CN"),
        new Tuple<X509NameLabel, string>(X509NameLabel.CN,"Sockets TEST TCP Server")
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

```

```c#

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

```

## BUG

BouncyCastle 1.9.0

1. The signature algorithm SHA256withECDSA points to SHA224withECDSA at Org.BouncyCastle.Cms.DefaultSignatureAlgorithmIdentifierFinder.
2. GCM cipher mode cannot be resue. The algorithm instance needs to be recreated every time.
3. SM2Signer does not reset the hash algorithm automatically. must be Reset() manually.
4. RC5-32, RC5-64 does not support KeyParameter, only RC5Parameters. (feature?)

## License

The development and release of this project is based on MIT licence.
