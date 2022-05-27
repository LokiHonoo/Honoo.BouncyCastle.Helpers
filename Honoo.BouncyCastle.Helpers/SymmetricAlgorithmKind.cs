using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm kind.
    /// </summary>
    [Flags]
    public enum SymmetricAlgorithmKind
    {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

        Block = 1,
        Stream

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}