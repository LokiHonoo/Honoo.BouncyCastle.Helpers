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
    - [ECDH](#ecdh)
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
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    // example 1
    byte[] hash1 = HashAlgorithmHelper.SHA3_256.ComputeHash(test);
    // example 2
    IDigest digest = HashAlgorithmHelper.SHA3_256.GenerateDigest();
    byte[] hash2 = new byte[HashAlgorithmHelper.SHA3_256.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash2, 0);
}

```

### HMAC

```c#

private static void Demo2()
{
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    byte[] key = new byte[72]; // Any value
    Utilities.Random.NextBytes(key);
    ICipherParameters parameters = HMACHelper.SHA3_256_HMAC.GenerateParameters(key);
    // example 1
    byte[] hash1 = HMACHelper.SHA3_256_HMAC.ComputeHash(parameters, test);
    // example 2
    IMac digest = HMACHelper.SHA3_256_HMAC.GenerateDigest(parameters);
    byte[] hash2 = new byte[HMACHelper.SHA3_256_HMAC.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash2, 0);
}

```

### CMAC

```c#

private static void Demo3()
{
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    byte[] key = new byte[128 / 8]; // AES key size
    Utilities.Random.NextBytes(key);
    ICipherParameters parameters = CMACHelper.AES_CMAC.GenerateParameters(key);
    // example 1
    byte[] hash1 = CMACHelper.AES_CMAC.ComputeHash(parameters, test);
    // example 2
    IMac digest = CMACHelper.AES_CMAC.GenerateDigest(parameters);
    byte[] hash = new byte[CMACHelper.AES_CMAC.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash, 0);
}

```

### MAC

```c#

private static void Demo4()
{
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    byte[] key = new byte[128 / 8]; // AES key size
    Utilities.Random.NextBytes(key);
    byte[] iv = new byte[128 / 8]; // AES IV size
    Utilities.Random.NextBytes(iv);
    ICipherParameters parameters = MACHelper.AES_MAC.GenerateParameters(key, iv);
    // example 1
    byte[] hash1 = MACHelper.AES_MAC.ComputeHash(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters, test);
    // example 2
    IMac digest = MACHelper.AES_MAC.GenerateDigest(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters);
    byte[] hash = new byte[MACHelper.AES_MAC.HashSize / 8];
    digest.BlockUpdate(test, 0, test.Length);
    digest.DoFinal(hash, 0);
}

```

### Symmetric encryption

```c#

private static void Demo1()
{
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    byte[] key = new byte[128 / 8]; // AES key size
    Utilities.Random.NextBytes(key);
    byte[] iv = new byte[128 / 8]; // AES IV size
    Utilities.Random.NextBytes(iv);
    ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, iv);
    // example 1
    byte[] enc1 = SymmetricAlgorithmHelper.AES.Encrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, test, 0, test.Length);
    _ = SymmetricAlgorithmHelper.AES.Decrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, enc1, 0, enc1.Length);
    // example 2
    IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateEncryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateDecryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
    byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
    _ = decryptor.DoFinal(enc2, 0, enc2.Length);
}

private static void Demo2()
{
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    byte[] key = new byte[128 / 8]; // AES key size
    Utilities.Random.NextBytes(key);
    byte[] nonce = new byte[104 / 8]; // SymmetricCipherMode.CCM legal
    Utilities.Random.NextBytes(nonce);
    int macSize = 96; // SymmetricCipherMode.CCM legal
    ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, nonce, macSize, null);
    // example 1
    byte[] enc1 = SymmetricAlgorithmHelper.AES.Encrypt(SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters, test, 0, test.Length);
    _ = SymmetricAlgorithmHelper.AES.Decrypt(SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters, enc1, 0, enc1.Length);
    // example 2
    IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateEncryptor(SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateDecryptor(SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters);
    byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
    _ = decryptor.DoFinal(enc2, 0, enc2.Length);
}

private static void Demo3()
{
    byte[] test = new byte[123];
    Utilities.Random.NextBytes(test);
    byte[] key = new byte[128 / 8]; // HC128 key size
    Utilities.Random.NextBytes(key);
    byte[] iv = new byte[128 / 8]; // HC128 IV size
    Utilities.Random.NextBytes(iv);
    ICipherParameters parameters = SymmetricAlgorithmHelper.HC128.GenerateParameters(key, iv);
    // example 1
    byte[] enc1 = SymmetricAlgorithmHelper.HC128.Encrypt(parameters, test, 0, test.Length);
    _ = SymmetricAlgorithmHelper.HC128.Decrypt(parameters, enc1, 0, enc1.Length);
    // example 2
    IBufferedCipher encryptor = SymmetricAlgorithmHelper.HC128.GenerateEncryptor(parameters);
    IBufferedCipher decryptor = SymmetricAlgorithmHelper.HC128.GenerateDecryptor(parameters);
    byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
    _ = decryptor.DoFinal(enc2, 0, enc2.Length);
}

```

### Asymmetric encryption

```c#

private static void Demo1()
{
    byte[] test = new byte[5];
    Utilities.Random.NextBytes(test);
    AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
    // example 1
    byte[] enc1 = AsymmetricAlgorithmHelper.RSA.Encrypt(AsymmetricPaddingMode.PKCS1, keyPair.Public, test, 0, test.Length);
    _ = AsymmetricAlgorithmHelper.RSA.Decrypt(AsymmetricPaddingMode.PKCS1, keyPair.Private, enc1, 0, enc1.Length);
    // example 2
    IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateEncryptor(AsymmetricPaddingMode.PKCS1, keyPair.Public);
    IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateDecryptor(AsymmetricPaddingMode.PKCS1, keyPair.Private);
    byte[] enc2 = encryptor.ProcessBlock(test, 0, test.Length);
    byte[] dec2 = decryptor.ProcessBlock(enc2, 0, enc2.Length);
    //
    Console.WriteLine(BitConverter.ToString(test).Replace("-", ""));
    Console.WriteLine(BitConverter.ToString(dec2).Replace("-", ""));
}

```

### Signature

```c#

private static void Demo1()
{
    byte[] test = new byte[83];
    Utilities.Random.NextBytes(test);
    AsymmetricCipherKeyPair keyPair = SignatureAlgorithmHelper.SHA256withECDSA.GenerateKeyPair();
    // example 1
    byte[] signature1 = SignatureAlgorithmHelper.SHA256withECDSA.Sign(keyPair.Private, test);
    bool same1 = SignatureAlgorithmHelper.SHA256withECDSA.Verify(keyPair.Public, test, signature1);
    // example 2
    ISigner signer = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner(keyPair.Private);
    ISigner verifier = SignatureAlgorithmHelper.SHA256withECDSA.GenerateVerifier(keyPair.Public);
    signer.BlockUpdate(test, 0, test.Length);
    byte[] signature2 = signer.GenerateSignature();
    verifier.BlockUpdate(test, 0, test.Length);
    bool same2 = verifier.VerifySignature(signature2);
}

```

### Certificate

```c#

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

```

### ECDH

```c#

private static void Demo1()
{
    //
    // Alice work.
    //
    IECDHTerminalA terminalA = AsymmetricAlgorithmHelper.ECDH.GenerateTerminalA(256);
    // Send exchangeA to Bob.
    byte[] exchangeToBob = terminalA.ExchangeA;
    //
    // Bob work.
    //
    IECDHTerminalB terminalB = AsymmetricAlgorithmHelper.ECDH.GenerateTerminalB(exchangeToBob);
    byte[] pmsB = terminalB.DeriveKeyMaterial();
    // Send exchangeB to Alice.
    byte[] exchangeToAlice = terminalB.ExchangeB;
    //
    // Alice work.
    //
    byte[] pmsA = terminalA.DeriveKeyMaterial(exchangeToAlice);
    //
    //
    //
    Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", ""));
    Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", ""));
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
