using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDSA elliptic curve.
    /// </summary>
    public enum ECDSAEllipticCurve
    {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

        SecT113r1 = 1, SecT113r2,
        SecT131r2, SecT131r1,
        SecT163k1, SecT163r1, SecT163r2,
        SecT193r1, SecT193r2,
        SecT233k1, SecT233r1,
        SecT239k1,
        SecT283k1, SecT283r1,
        SecT409k1, SecT409r1,
        SecT571k1, SecT571r1,
        SecP112r1, SecP112r2,
        SecP128r1, SecP128r2,
        SecP160k1, SecP160r1, SecP160r2,
        SecP192k1, SecP192r1,
        SecP224k1, SecP224r1,
        SecP256k1, SecP256r1,
        SecP384r1,
        SecP521r1,

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}