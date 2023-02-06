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
    // example 1
    _ = HashAlgorithms.SHA3_256.ComputeHash(_input);
    // example 2
    IDigest digest = HashAlgorithms.SHA3_256.GenerateDigest();
    byte[] hash = new byte[HashAlgorithms.SHA3_256.HashSize / 8];
    digest.BlockUpdate(_input, 0, _input.Length);
    digest.DoFinal(hash, 0);
}

```

### HMAC

```c#

private static void Demo2()
{
    byte[] key = new byte[71]; // Any value
    Utilities.Random.NextBytes(key);
    ICipherParameters parameters = HMACAlgorithms.SHA3_256_HMAC.GenerateParameters(key);
    // example 1
    _ = HMACAlgorithms.SHA3_256_HMAC.ComputeHash(parameters, _input);
    // example 2
    IMac digest = HMACAlgorithms.SHA3_256_HMAC.GenerateDigest(parameters);
    byte[] hash = new byte[HMACAlgorithms.SHA3_256_HMAC.HashSize / 8];
    digest.BlockUpdate(_input, 0, _input.Length);
    digest.DoFinal(hash, 0);
}

```

### CMAC

```c#

private static void Demo3()
{
    byte[] key = new byte[128 / 8]; // AES key size
    Utilities.Random.NextBytes(key);
    ICipherParameters parameters = CMACAlgorithms.AES_CMAC.GenerateParameters(key);
    // example 1
    _ = CMACAlgorithms.AES_CMAC.ComputeHash(parameters, _input);
    // example 2
    IMac digest = CMACAlgorithms.AES_CMAC.GenerateDigest(parameters);
    byte[] hash = new byte[CMACAlgorithms.AES_CMAC.HashSize / 8];
    digest.BlockUpdate(_input, 0, _input.Length);
    digest.DoFinal(hash, 0);
}

```

### MAC

```c#

private static void Demo4()
{
    byte[] key = new byte[128 / 8]; // AES key size
    Utilities.Random.NextBytes(key);
    byte[] iv = new byte[128 / 8]; // AES IV size
    Utilities.Random.NextBytes(iv);
    ICipherParameters parameters = MACAlgorithms.AES_MAC.GenerateParameters(key, iv);
    // example 1
    _ = MACAlgorithms.AES_MAC.ComputeHash(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters, _input);
    // example 2
    IMac digest = MACAlgorithms.AES_MAC.GenerateDigest(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters);
    byte[] hash = new byte[MACAlgorithms.AES_MAC.HashSize / 8];
    digest.BlockUpdate(_input, 0, _input.Length);
    digest.DoFinal(hash, 0);
}

```

### Symmetric encryption

```c#

private static void Demo1()
{
    byte[] key = new byte[128 / 8];
    Utilities.Random.NextBytes(key);
    byte[] iv = new byte[128 / 8];
    Utilities.Random.NextBytes(iv);
    ICipherParameters parameters = SymmetricAlgorithms.AES.GenerateParameters(key, iv);
    // example 1
    byte[] enc = SymmetricAlgorithms.AES.Encrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, _input, 0, _input.Length);
    _ = SymmetricAlgorithms.AES.Decrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, enc, 0, enc.Length);
    // example 2
    IBufferedCipher encryptor = SymmetricAlgorithms.AES.GenerateEncryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithms.AES.GenerateDecryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
    enc = encryptor.DoFinal(_input, 0, _input.Length);
    _ = decryptor.DoFinal(enc, 0, enc.Length);
}

private static void Demo2()
{
    byte[] key = new byte[128 / 8];
    Utilities.Random.NextBytes(key);
    byte[] nonce = new byte[64 / 8]; // See SymmetricCipherMode.GCM summary
    Utilities.Random.NextBytes(nonce);
    int macSize = 96; // See SymmetricCipherMode.GCM summary
    ICipherParameters parameters = SymmetricAlgorithms.AES.GenerateParameters(key, nonce, macSize, null);
    // example 1
    byte[] enc = SymmetricAlgorithms.AES.Encrypt(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters, _input, 0, _input.Length);
    _ = SymmetricAlgorithms.AES.Decrypt(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters, enc, 0, enc.Length);
    // example 2
    IBufferedCipher encryptor = SymmetricAlgorithms.AES.GenerateEncryptor(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters);
    IBufferedCipher decryptor = SymmetricAlgorithms.AES.GenerateDecryptor(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters);
    byte[] enc2 = encryptor.DoFinal(_input, 0, _input.Length);
    _ = decryptor.DoFinal(enc2, 0, enc2.Length);
}

private static void Demo3()
{
    byte[] key = new byte[128 / 8]; 
    Utilities.Random.NextBytes(key);
    byte[] iv = new byte[128 / 8];
    Utilities.Random.NextBytes(iv);
    ICipherParameters parameters = SymmetricAlgorithms.HC128.GenerateParameters(key, iv);
    // example 1
    byte[] enc = SymmetricAlgorithms.HC128.Encrypt(parameters, _input, 0, _input.Length);
    _ = SymmetricAlgorithms.HC128.Decrypt(parameters, enc, 0, enc.Length);
    // example 2
    IBufferedCipher encryptor = SymmetricAlgorithms.HC128.GenerateEncryptor(parameters);
    IBufferedCipher decryptor = SymmetricAlgorithms.HC128.GenerateDecryptor(parameters);
    byte[] enc2 = encryptor.DoFinal(_input, 0, _input.Length);
    _ = decryptor.DoFinal(enc2, 0, enc2.Length);
}

```

### Asymmetric encryption

```c#

private static void Demo1()
{
    AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithms.RSA.GenerateKeyPair();
    // example 1
    byte[] enc = AsymmetricAlgorithms.RSA.Encrypt(AsymmetricPaddingMode.PKCS1, keyPair.Public, _input, 0, _input.Length);
    _ = AsymmetricAlgorithms.RSA.Decrypt(AsymmetricPaddingMode.PKCS1, keyPair.Private, enc, 0, enc.Length);
    // example 2
    IAsymmetricBlockCipher encryptor = AsymmetricAlgorithms.RSA.GenerateEncryptor(AsymmetricPaddingMode.PKCS1, keyPair.Public);
    IAsymmetricBlockCipher decryptor = AsymmetricAlgorithms.RSA.GenerateDecryptor(AsymmetricPaddingMode.PKCS1, keyPair.Private);
    enc = encryptor.ProcessBlock(_input, 0, _input.Length);
    _ = decryptor.ProcessBlock(enc, 0, enc.Length);
}

```

### Signature

```c#

private static void Demo1()
{
    AsymmetricCipherKeyPair keyPair = SignatureAlgorithms.SHA256withECDSA.AsymmetricAlgorithm.GenerateKeyPair();
    // example 1
    byte[] signature = SignatureAlgorithms.SHA256withECDSA.Sign(keyPair.Private, _input);
    _ = SignatureAlgorithms.SHA256withECDSA.Verify(keyPair.Public, _input, signature);
    // example 2
    ISigner signer = SignatureAlgorithms.SHA256withECDSA.GenerateSigner(keyPair.Private);
    ISigner verifier = SignatureAlgorithms.SHA256withECDSA.GenerateVerifier(keyPair.Public);
    signer.BlockUpdate(_input, 0, _input.Length);
    signature = signer.GenerateSignature();
    verifier.BlockUpdate(_input, 0, _input.Length);
    _ = verifier.VerifySignature(signature);
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
    AsymmetricCipherKeyPair caKeyPair = caSignatureAlgorithm.AsymmetricAlgorithm.GenerateKeyPair();
    //
    X509NameEntity[] caDN = new X509NameEntity[]
    {
        new X509NameEntity(X509NameLabel.C,"CN"),
        new X509NameEntity(X509NameLabel.CN,"TEST Root CA")
    };
    X509ExtensionEntity[] caExtensions = new X509ExtensionEntity[]
    {
        new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
        new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
    };
    X509Certificate caCert = X509Helper.GenerateIssuerCertificate(caSignatureAlgorithm,
                                                                    caKeyPair,
                                                                    caDN,
                                                                    caExtensions,
                                                                    DateTime.UtcNow.AddDays(-3),
                                                                    DateTime.UtcNow.AddDays(120));
    X509RevocationEntity[] revocationEntities = new X509RevocationEntity[]
    {
        new X509RevocationEntity(new BigInteger("12345678901"), DateTime.UtcNow.AddDays(-2), null),
        new X509RevocationEntity(new BigInteger("12345678902"), DateTime.UtcNow.AddDays(-2), null)
    };

    X509Crl caCrl = X509Helper.GenerateCrl(caSignatureAlgorithm,
                                            caKeyPair.Private,
                                            caCert,
                                            revocationEntities,
                                            null,
                                            DateTime.UtcNow.AddDays(-2),
                                            DateTime.UtcNow.AddDays(30));
    //
    // User create csr and sand to CA.
    //
    AsymmetricCipherKeyPair userKeyPair = SignatureAlgorithms.GOST3411withECGOST3410.AsymmetricAlgorithm.GenerateKeyPair();
    X509NameEntity[] userDN = new X509NameEntity[]
    {
        new X509NameEntity(X509NameLabel.C,"CN"),
        new X509NameEntity(X509NameLabel.CN,"TEST User")
    };
    X509ExtensionEntity[] userExtensions = null;
    Pkcs10CertificationRequest userCsr = X509Helper.GenerateCsr(SignatureAlgorithms.GOST3411withECGOST3410, userKeyPair, userDN, userExtensions);
    //
    // CA extract csr and create user cert.
    //
    X509Helper.ExtractCsr(userCsr,
                            out AsymmetricKeyParameter userPublicKey,
                            out IList<X509NameEntity> userDNExtracted,
                            out IList<X509ExtensionEntity> userExtensionsExtracted);
    X509Certificate userCert = X509Helper.GenerateSubjectCertificate(userSignatureAlgorithmName,
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
    Console.WriteLine("====  CA Cert  ===========================");
    Console.WriteLine(caCert.ToString());
    Console.WriteLine("====  CA Crl  ============================");
    Console.WriteLine(caCrl.ToString());
    Console.WriteLine("====  User Cert  =========================");
    Console.WriteLine(userCert.ToString());
    Console.WriteLine();
    //
    // User verify cert.
    //
    bool validated;
    try
    {
        caCrl.Verify(caCert.GetPublicKey());
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
    IECDHTerminalA terminalA = AsymmetricAlgorithms.ECDH.GenerateTerminalA(256);
    // Send to Bob.
    byte[] publicKeyA = terminalA.PublicKey;
    byte[] pA = terminalA.P;
    byte[] gA = terminalA.G;
    //
    // Bob work.
    //
    IECDHTerminalB terminalB = AsymmetricAlgorithms.ECDH.GenerateTerminalB(publicKeyA, pA, gA);
    byte[] pmsB = terminalB.DeriveKeyMaterial(true);
    // Send to Alice.
    byte[] publicKeyB = terminalB.PublicKey;
    //
    // Alice work.
    //
    byte[] pmsA = terminalA.DeriveKeyMaterial(publicKeyB, true);
    //
    //
    //
    Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", "") + "  " + pmsA.Length + " bytes.");
    Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", "") + "  " + pmsB.Length + " bytes.");
}

```

## BUG

BouncyCastle 1.9.0 has not been fixed

1. RC5-32, RC5-64 does not support KeyParameter, only RC5Parameters. (feature?)
2. GCM cipher mode cannot be resue. The algorithm instance needs to be recreated every time.
3. OCB cipher mode supported null(0) Nonce/IV size but BouncyCastle cannot set that.
4. The signature algorithm SHA256withECDSA points to SHA224withECDSA at Org.BouncyCastle.Cms.DefaultSignatureAlgorithmIdentifierFinder.
5. SM2Signer does not reset the hash algorithm automatically. must be Reset() manually.

## License

The development and release of this project is based on MIT licence.
