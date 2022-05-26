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
    _ = decryptor.ProcessBlock(enc2, 0, enc2.Length);
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

```

```c#

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

```

```c#

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

```

### ECDH

```c#

private static void Demo1()
{
    //
    // Alice work.
    //
    DHParameters parametersA = AsymmetricAlgorithmHelper.ECDH.GenerateParametersA(256, 25);
    AsymmetricCipherKeyPair keyPairA = AsymmetricAlgorithmHelper.ECDH.GenerateKeyPair(parametersA);
    string publicKeyAString = PemHelper.KeyToPem(keyPairA.Public);
    string p = parametersA.P.ToString();
    string g = parametersA.G.ToString();
    //
    // Bob work.
    //
    AsymmetricKeyParameter publicKeyA = PemHelper.PemToKey(publicKeyAString);
    Org.BouncyCastle.Math.BigInteger parametersAP = new Org.BouncyCastle.Math.BigInteger(p);
    Org.BouncyCastle.Math.BigInteger parametersAG = new Org.BouncyCastle.Math.BigInteger(g);
    DHParameters parametersB = AsymmetricAlgorithmHelper.ECDH.GenerateParametersB(parametersAP, parametersAG);
    AsymmetricCipherKeyPair keyPairB = AsymmetricAlgorithmHelper.ECDH.GenerateKeyPair(parametersB);
    IBasicAgreement agreementB = AsymmetricAlgorithmHelper.ECDH.GenerateAgreement(keyPairB.Private);
    byte[] pmsB = agreementB.CalculateAgreement(publicKeyA).ToByteArrayUnsigned();
    string publicKeyBString = PemHelper.KeyToPem(keyPairB.Public);
    //
    // Alice work.
    //
    AsymmetricKeyParameter publicKeyB = PemHelper.PemToKey(publicKeyBString);
    IBasicAgreement agreementA = AsymmetricAlgorithmHelper.ECDH.GenerateAgreement(keyPairA.Private);
    byte[] pmsA = agreementA.CalculateAgreement(publicKeyB).ToByteArrayUnsigned();
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
