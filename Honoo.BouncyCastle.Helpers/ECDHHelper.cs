using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDH helper.
    /// </summary>
    public static class ECDHHelper
    {
        /// <summary>
        /// Create ECDH agreement.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static IBasicAgreement CreateAgreement(DHParameters parameters, out AsymmetricKeyParameter publicKey)
        {
            IAsymmetricCipherKeyPairGenerator generator =      GeneratorUtilities.GetKeyPairGenerator("ECDH");
            DHKeyGenerationParameters parameters2 = new DHKeyGenerationParameters(Common.ThreadSecureRandom.Value, parameters);


            DHKeyPairGenerator aa = new DHKeyPairGenerator(); ;
            aa.Init(parameters2);





            generator.Init(parameters2);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            agreement.Init(keyPair.Private);
            publicKey = keyPair.Public;
            return agreement;
        }

        internal byte[] DeriveKeyMaterial(byte[] publicKeyBytes)
        {
            Org.BouncyCastle.Apache.Bzip2.BZip2Constants bZip2Constants = new Org.BouncyCastle.Apache.Bzip2.BZip2Constants();
          
            Org.BouncyCastle.Apache.Bzip2.BZip2Constants  .CBZip2InputStream aaaaa = new Org.BouncyCastle.Apache.Bzip2.CBZip2InputStream();
            aaaaa.
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(publicKeyBytes);
            return _agreement.CalculateAgreement(publicKey).ToByteArrayUnsigned();
        }

        /// <summary>
        /// Create ECDH parameters A.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="certainty">Certainty. 25</param>
        /// <returns></returns>
        public static DHParameters CreateParametersA(int keySize,int certainty)
        {
            DHParametersGenerator generator = new DHParametersGenerator();
            generator.Init(keySize, certainty, Common.ThreadSecureRandom.Value);
            return generator.GenerateParameters();
        }

        public static DHParameters CreateParametersB(BigInteger aP, BigInteger aG)
        {
            var aa= new DHKeyPairGenerator(); ;
            aa.Init
            System.Security.Cryptography.ECDiffieHellman.Create( eCDiffieHellman = new System.Security.Cryptography.ECDiffieHellman();
            eCDiffieHellman.
            return new DHParameters(aP, aG);
        }
    }
}
