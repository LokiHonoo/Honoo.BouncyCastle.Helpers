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

        Signature = 1,
        Encryption = 2,
        Both = Signature | Encryption,
        KeyExchange = 4,
#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}