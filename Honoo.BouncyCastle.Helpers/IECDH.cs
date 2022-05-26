using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDH.
    /// </summary>
    public interface IECDH
    {
        /// <summary>
        /// Derive key material from the other asymmetric public key.
        /// </summary>
        /// <param name="agreement">Agreement.</param>
        /// <param name="otherPublicKey">The other asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] DeriveKeyMaterial(IBasicAgreement agreement, AsymmetricKeyParameter otherPublicKey);

        /// <summary>
        /// Generate agreement.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBasicAgreement GenerateAgreement(AsymmetricKeyParameter privateKey);

        /// <summary>
        /// Generate key pair. NOT Implemented.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        AsymmetricCipherKeyPair GenerateKeyPair(DHParameters parameters);

        /// <summary>
        /// Generate parameters Alice.
        /// <para/>Uses key size 256 bits, certainty 25 by default.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        DHParameters GenerateParametersA();

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        DHParameters GenerateParametersA(int keySize, int certainty);

        /// <summary>
        /// Generate parameters Bob.
        /// </summary>
        /// <param name="aP">ParametersA P.</param>
        /// <param name="aG">ParametersA G.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        DHParameters GenerateParametersB(BigInteger aP, BigInteger aG);
    }
}