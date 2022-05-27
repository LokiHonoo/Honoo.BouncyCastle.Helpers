using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric algorithm kind.
    /// </summary>
    [Flags]
    public enum AsymmetricAlgorithmKind
    {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释
        Neither = 1,
        Signature = 2,
        Encryption = 4,
        Both = Signature | Encryption

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}