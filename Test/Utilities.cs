using System;

namespace Test
{
    internal static class Utilities
    {
        private static readonly byte[] _pool = new byte[1048576];
        internal static Random Random = new Random();
    }
}