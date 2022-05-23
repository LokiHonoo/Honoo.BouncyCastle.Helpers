using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {
            Console.WriteLine("case \"" + X9ObjectIdentifiers.ECDsaWithSha1.Id + "\": oid = X9ObjectIdentifiers.ECDsaWithSha1;return true;");
            Console.WriteLine("case \"" + X9ObjectIdentifiers.ECDsaWithSha224.Id + "\": oid = X9ObjectIdentifiers.ECDsaWithSha224;return true;");
            Console.WriteLine("case \"" + X9ObjectIdentifiers.ECDsaWithSha256.Id + "\": oid = X9ObjectIdentifiers.ECDsaWithSha256;return true;");
            Console.WriteLine("case \"" + X9ObjectIdentifiers.ECDsaWithSha384.Id + "\": oid = X9ObjectIdentifiers.ECDsaWithSha384;return true;");
            Console.WriteLine("case \"" + X9ObjectIdentifiers.ECDsaWithSha512.Id + "\": oid = X9ObjectIdentifiers.ECDsaWithSha512;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdEcdsaWithSha3_224.Id + "\": oid = NistObjectIdentifiers.IdEcdsaWithSha3_224;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdEcdsaWithSha3_256.Id + "\": oid = NistObjectIdentifiers.IdEcdsaWithSha3_256;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdEcdsaWithSha3_384.Id + "\": oid = NistObjectIdentifiers.IdEcdsaWithSha3_384;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdEcdsaWithSha3_512.Id + "\": oid = NistObjectIdentifiers.IdEcdsaWithSha3_512;return true;");
            Console.WriteLine();

           Console.WriteLine("case \"" + EacObjectIdentifiers.id_TA_ECDSA_SHA_1.Id + "\": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_1;return true;");
            Console.WriteLine("case \"" + EacObjectIdentifiers.id_TA_ECDSA_SHA_224.Id + "\": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_224;return true;");
            Console.WriteLine("case \"" + EacObjectIdentifiers.id_TA_ECDSA_SHA_256.Id + "\": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_256;return true;");
            Console.WriteLine("case \"" + EacObjectIdentifiers.id_TA_ECDSA_SHA_384.Id + "\": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_384;return true;");
            Console.WriteLine("case \"" + EacObjectIdentifiers.id_TA_ECDSA_SHA_512.Id + "\": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_512;return true;");
            Console.WriteLine();
            Console.WriteLine("case \"" + BsiObjectIdentifiers.ecdsa_plain_RIPEMD160.Id + "\": oid = BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;return true;");
            Console.WriteLine("case \"" + BsiObjectIdentifiers.ecdsa_plain_SHA1.Id + "\": oid = BsiObjectIdentifiers.ecdsa_plain_SHA1;return true;");
            Console.WriteLine("case \"" + BsiObjectIdentifiers.ecdsa_plain_SHA224.Id + "\": oid = BsiObjectIdentifiers.ecdsa_plain_SHA224;return true;");
            Console.WriteLine("case \"" + BsiObjectIdentifiers.ecdsa_plain_SHA256.Id + "\": oid = BsiObjectIdentifiers.ecdsa_plain_SHA256;return true;");
            Console.WriteLine("case \"" + BsiObjectIdentifiers.ecdsa_plain_SHA384.Id + "\": oid = BsiObjectIdentifiers.ecdsa_plain_SHA384;return true;");
            Console.WriteLine("case \"" + BsiObjectIdentifiers.ecdsa_plain_SHA512.Id + "\": oid = BsiObjectIdentifiers.ecdsa_plain_SHA512;return true;");
            Console.WriteLine();
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.IdRsassaPss.Id + "\": oid = PkcsObjectIdentifiers.IdRsassaPss;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.IdRsassaPss.Id + "\": oid = PkcsObjectIdentifiers.IdRsassaPss;return true;");
            Console.WriteLine();
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.MD2WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.MD2WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.MD5WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.MD5WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128.Id + "\": oid = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;return true;");
            Console.WriteLine("case \"" + TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160.Id + "\": oid = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;return true;");
            Console.WriteLine("case \"" + TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256.Id + "\": oid = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.Sha1WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.Sha224WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.Sha224WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.Sha256WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.Sha384WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.Sha384WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id + "\": oid = PkcsObjectIdentifiers.Sha512WithRsaEncryption;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224.Id + "\": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256.Id + "\": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384.Id + "\": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512.Id + "\": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;return true;");

            Console.WriteLine();

            Console.WriteLine("case \"" + X9ObjectIdentifiers.IdDsaWithSha1.Id + "\": oid = X9ObjectIdentifiers.IdDsaWithSha1;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.DsaWithSha224.Id + "\": oid = NistObjectIdentifiers.DsaWithSha224;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.DsaWithSha256.Id + "\": oid = NistObjectIdentifiers.DsaWithSha256;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.DsaWithSha384.Id + "\": oid = NistObjectIdentifiers.DsaWithSha384;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.DsaWithSha512.Id + "\": oid = NistObjectIdentifiers.DsaWithSha512;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdDsaWithSha3_224.Id + "\": oid = NistObjectIdentifiers.IdDsaWithSha3_224;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdDsaWithSha3_256.Id + "\": oid = NistObjectIdentifiers.IdDsaWithSha3_256;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdDsaWithSha3_384.Id + "\": oid = NistObjectIdentifiers.IdDsaWithSha3_384;return true;");
            Console.WriteLine("case \"" + NistObjectIdentifiers.IdDsaWithSha3_512.Id + "\": oid = NistObjectIdentifiers.IdDsaWithSha3_512;return true;");

            Console.WriteLine();
            Console.WriteLine("case \"" + CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.Id + "\": oid = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;return true;");
            Console.WriteLine("case \"" + CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.Id + "\": oid = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;return true;");
            Console.WriteLine();
            Console.WriteLine("case \"" + GMObjectIdentifiers.sm2sign_with_sha256.Id + "\": oid = GMObjectIdentifiers.sm2sign_with_sha256;return true;");
            Console.WriteLine("case \"" + GMObjectIdentifiers.sm2sign_with_sm3.Id + "\": oid = GMObjectIdentifiers.sm2sign_with_sm3;return true;");



            //
            Console.WriteLine("\r\n\r\n");


        }
    }
}