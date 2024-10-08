# Honoo.BouncyCastle.Helpers

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Honoo.BouncyCastle.Helpers](#honoobouncycastlehelpers)
  - [INTRODUCTION](#introduction)
  - [GUIDE](#guide)
    - [NuGet](#nuget)
  - [USAGE](#usage)
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
  - [LICENSE](#license)

<!-- /code_chunk_output -->

## INTRODUCTION

BouncyCastle's helpers. Refactoring by System.Security.Cryptography code styles.

## GUIDE

### NuGet

<https://www.nuget.org/packages/Honoo.BouncyCastle.Helpers/>

## USAGE

### Namespace

```c#

using Honoo.BouncyCastle.Helpers;

```

### Hash

```c#

private static void Demo1()
{
    SHA1 sha1 = new SHA1();
    _ = sha1.ComputeFinal(_input);

    HashAlgorithm sha256 = HashAlgorithm.Create(HashAlgorithmName.SHA256);
    sha256.Update(_input);
    _ = sha256.ComputeFinal();
}

```

### HMAC

```c#

private static void Demo2()
{
    HMAC hmac1 = HMAC.Create(HMACName.HMAC_SM3);
    byte[] key = new byte[66]; // Any length.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    hmac1.ImportParameters(key);
    _ = hmac1.ComputeFinal(_input);
}

```

### CMAC

```c#

private static void Demo3()
{
    CMAC cmac1 = CMAC.Create(CMACName.AES_CMAC);
    byte[] key = new byte[192 / 8]; // 192 = AES legal key size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    cmac1.ImportParameters(key);
    _ = cmac1.ComputeFinal(_input);
}

```

### MAC

```c#

private static void Demo4()
{
    MAC mac1 = MAC.Create(MACName.Rijndael224_MAC);
    mac1.Mode = SymmetricCipherMode.CBC;
    mac1.Padding = SymmetricPaddingMode.TBC;
    byte[] key = new byte[160 / 8];  // 160 = Rijndael224 legal key size bits.
    byte[] iv = new byte[224 / 8];   // 224 = CBC mode limit same as Rijndael224 block size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
    mac1.ImportParameters(key, iv);
    _ = mac1.ComputeFinal(_input);
}

```

### Symmetric encryption

```c#

private static void Demo1()
{
    SymmetricAlgorithm alg1 = SymmetricAlgorithm.Create(SymmetricAlgorithmName.Rijndael224);
    alg1.Mode = SymmetricCipherMode.CTR;
    alg1.Padding = SymmetricPaddingMode.TBC;
    Rijndael alg2 = new Rijndael(224) { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
    byte[] key = new byte[160 / 8];  // 160 = Rijndael224 legal key size bits.
    byte[] iv = new byte[224 / 8];   // 224 = CTR mode limit same as Rijndael block size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
    alg1.ImportParameters(key, iv);
    alg2.ImportParameters(key, iv);
    byte[] enc = alg1.EncryptFinal(_input);
    _ = alg2.DecryptFinal(enc);
}

private static void Demo3()
{
    SymmetricAlgorithm alg1 = SymmetricAlgorithm.Create(SymmetricAlgorithmName.HC128);
    HC128 alg2 = new HC128();
    byte[] key = new byte[128 / 8];  // 128 = HC128 legal key size bits.
    byte[] iv = new byte[128 / 8];   // 128 = HC128 legal iv size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
    alg1.ImportParameters(key, iv);
    alg2.ImportParameters(key, iv);
    byte[] enc = alg1.EncryptFinal(_input);
    _ = alg2.DecryptFinal(enc);
}

```

### Asymmetric encryption

```c#

private static void Demo1()
{
    RSA rsa1 = new RSA();
    rsa1.GenerateParameters(2048);
    string publicKeyPem = rsa1.ExportPem(false);

    RSA rsa2 = (RSA)AsymmetricAlgorithm.Create(AsymmetricAlgorithmName.RSA);
    rsa2.ImportPem(publicKeyPem);

    byte[] enc = rsa2.Encrypt(_input);
    byte[] dec = rsa1.Decrypt(enc);
}

```

### Signature

```c#

private static void Demo()
{
    ECDSA alg1 = (ECDSA)AsymmetricAlgorithm.Create(SignatureAlgorithmName.SHA256withECDSA);
    string publicKeyPem = alg1.ExportPem(false);
    byte[] signature = alg1.SignFinal(_input);

    if (SignatureAlgorithmName.TryGetAlgorithmName("sha256withecdsa", out SignatureAlgorithmName name))
    {
        ISignatureAlgorithm alg2 = AsymmetricAlgorithm.Create(name);
        alg2.ImportPem(publicKeyPem);

        alg2.VerifyUpdate(_input);
        bool same = alg2.VerifyFinal(signature);
    }
}

```

### Certificate

```c#

private static void CreateCACert()
{
    //
    // Issuer work, Create CA private key and self sign certificate.
    //
    _issuerSignatureAlgorithm = SignatureAlgorithmName.SHA256withECDSA;
    ISignatureAlgorithm issuerAlgorithm = AsymmetricAlgorithm.Create(_issuerSignatureAlgorithm);
    byte[] issuerPrivateKeyInfo = issuerAlgorithm.ExportKeyInfo(true);
    X509CertificateRequestGenerator issuerCsrGenerator = new X509CertificateRequestGenerator(_issuerSignatureAlgorithm, issuerPrivateKeyInfo);
    issuerCsrGenerator.SubjectDN.Add(X509NameLabel.C, "CN");
    issuerCsrGenerator.SubjectDN.Add(X509NameLabel.CN, "Test CA");
    string issuerCsr = issuerCsrGenerator.GeneratePem();
    X509CertificateV3Generator v3Generator = new X509CertificateV3Generator(_issuerSignatureAlgorithm, issuerPrivateKeyInfo);
    v3Generator.IssuerDN.Add(X509NameLabel.C, "CN");
    v3Generator.IssuerDN.Add(X509NameLabel.CN, "Test CA");
    v3Generator.SetCertificateRequest(issuerCsr);
    _issuerCer = v3Generator.Generate(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(365));
    _issuerPrivateKeyInfo = issuerPrivateKeyInfo;
}

private static void CreateUserCert()
{
    //
    // Issuer work, Create key for subject.
    //
    SignatureAlgorithmName userSignatureAlgorithm = SignatureAlgorithmName.SM3withSM2; //Issuer define of allow user specify.
    ISignatureAlgorithm issuerCreateAlgorithmForSubject = AsymmetricAlgorithm.Create(userSignatureAlgorithm);
    string algorithmMechanism = userSignatureAlgorithm.Oid; // Send to user
    byte[] userPrivateKeyInfo = issuerCreateAlgorithmForSubject.ExportKeyInfo(true); // Send to user
    Org.BouncyCastle.Crypto.AsymmetricKeyParameter userPublicKey = issuerCreateAlgorithmForSubject.ExportParameters(false);

    //
    // User work, Create certificate request.
    //
    SignatureAlgorithmName.TryGetAlgorithmName(algorithmMechanism, out SignatureAlgorithmName userAlgorithmName);
    X509CertificateRequestGenerator userCreateCsr = new X509CertificateRequestGenerator(userAlgorithmName, userPrivateKeyInfo);
    userCreateCsr.SubjectDN.Add(new X509NameEntity(X509NameLabel.C, "CN"));
    userCreateCsr.SubjectDN.Add(new X509NameEntity(X509NameLabel.CN, "Test Subject Porject Name"));
    userCreateCsr.SubjectDN.Add(new X509NameEntity(X509NameLabel.EmailAddress, "abc999@test111222.com"));
    Asn1Encodable asn1 = new BasicConstraints(false);
    userCreateCsr.Extensions.Add(new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, asn1));
    byte[] csrPem = userCreateCsr.GenerateDer(); // Send to issuer

    //
    // Issuer work, Load certificate request and create certificate.
    //
    X509CertificateV3Generator v3generator = new X509CertificateV3Generator(_issuerSignatureAlgorithm, _issuerPrivateKeyInfo);
    v3generator.IssuerDN.CopyFromSubjectDN(_issuerCer);
    Asn1Encodable asn2 = new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.DataEncipherment);
    v3generator.Extensions.Add(new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, false, asn2));
    v3generator.SetCertificateRequest(csrPem);
    if (v3generator.CertificateRequest.Verify(userPublicKey))
    {
        v3generator.CertificateRequest.SubjectDN.Remove(X509NameLabel.EmailAddress);
    }
    byte[] userCer = v3generator.GenerateDer(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(99));
    //
    // User work, Verify.
    //
    File.WriteAllBytes("userCer.cer", userCer);
    var userCerBC = new Org.BouncyCastle.X509.X509Certificate(userCer);
    var userCerNET = new System.Security.Cryptography.X509Certificates.X509Certificate2(userCer); 
    try
    {
        userCerBC.Verify(_issuerCer.GetPublicKey());
        Console.WriteLine($"Verify user certificate by CA certificate - true");
    }
    catch (Exception)
    {
        Console.WriteLine($"Verify user certificate by CA certificate - false");
    }
    Console.WriteLine();
    Console.WriteLine(userCerBC);
    Console.WriteLine();
    Console.WriteLine(userCerNET);
    Console.ReadKey(true);
}

```

### ECDH

```c#

private static void Demo()
{
    // Alice work
    IKeyExchangeTerminalA keA = new ECDH().GetTerminalA();
    keA.GenerateParameters(384);
    byte[] p = keA.P;
    byte[] g = keA.G;
    byte[] publicKeyA = keA.PublicKeyA;

    // Bob work
    IKeyExchangeTerminalB keB = new ECDH().GetTerminalB();
    keB.GenerateParameters(p, g, publicKeyA);
    byte[] pmsB = keB.DeriveKeyMaterial(true);
    byte[] publicKeyB = keB.PublicKeyB;

    // Cracker work
    IKeyExchangeTerminalB keC = new ECDH().GetTerminalB();
    keC.GenerateParameters(p, g, publicKeyA);
    byte[] pmsC = keC.DeriveKeyMaterial(true);
    byte[] publicKeyC = keC.PublicKeyB;

    // Alice work
    byte[] pmsAB = keA.DeriveKeyMaterial(publicKeyB, true);
    byte[] pmsAC = keA.DeriveKeyMaterial(publicKeyC, true);

    //
    Console.WriteLine("    Alice-Bob pms:" + BitConverter.ToString(pmsAB).Replace("-", ""));
    Console.WriteLine("          Bob pms:" + BitConverter.ToString(pmsB).Replace("-", ""));
    Console.WriteLine();
    Console.WriteLine("Alice-Cracker pms:" + BitConverter.ToString(pmsAC).Replace("-", ""));
    Console.WriteLine("      Cracker pms:" + BitConverter.ToString(pmsC).Replace("-", ""));
}

```

## LICENSE

[MIT](LICENSE) license.

