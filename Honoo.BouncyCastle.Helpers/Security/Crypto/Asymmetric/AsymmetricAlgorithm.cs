using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric algorithm.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IEquatable<AsymmetricAlgorithm>, IAsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _kind;

        private readonly string _name;

        private readonly DerObjectIdentifier _oid;

        /// <summary>
        /// Asymmetric algorithm kind.
        /// </summary>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        ///// <summary>
        ///// Gets signature algorithm oid. It's maybe 'null' if not supported.
        ///// </summary>
        internal DerObjectIdentifier Oid => _oid;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Asymmetric algorithm.
        /// </summary>
        /// <param name="name">Asymmetric algorithm name.</param>
        /// <param name="oid">Asymmetric algorithm oid.</param>
        /// <param name="kind">Asymmetric algorithm kind.</param>
        protected AsymmetricAlgorithm(string name, DerObjectIdentifier oid, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _oid = oid;
            _kind = kind;
        }

        #endregion Construction

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(AsymmetricAlgorithm other)
        {
            return _name.Equals(other._name);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((AsymmetricAlgorithm)obj);
        }

        /// <summary>
        /// Generate key pair by default settings. Cast to algorithm class to replacement parameters.
        /// </summary>
        /// <returns></returns>
        public abstract AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Returns the hash code for this object.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}