namespace Verifiable.Core.Cryptography
{
    public static class CryptographicKeyFactory2
    {
        private static Func<Tag, string?, VerificationFunction<byte, byte, Signature, ValueTask<bool>>>? VerificationMapping { get; set; }
        private static Func<Tag, string?, SigningFunction<byte, byte, ValueTask<Signature>>>? SigningMapping { get; set; }


        /// <summary>
        /// Initializes the mappings for verification and signing functions.
        /// </summary>
        public static void Initialize(
            Func<Tag, string?, VerificationFunction<byte, byte, Signature, ValueTask<bool>>> verificationMapping,
            Func<Tag, string?, SigningFunction<byte, byte, ValueTask<Signature>>> signingMapping)
        {
            VerificationMapping = verificationMapping;
            SigningMapping = signingMapping;
        }

        /// <summary>
        /// Creates a public key object using the mapped verification function.
        /// </summary>
        public static PublicKey CreatePublicKey(
            PublicKeyMemory publicKeyMemory,
            string keyIdentifier,
            Tag tag,
            string? selector = null)
        {
            if(VerificationMapping == null)
            {
                throw new InvalidOperationException("Verification mapping has not been initialized.");
            }
            
            var verificationFunction = VerificationMapping(tag, selector) ?? throw new ArgumentException($"No verification function registered for {tag}, {selector}.");

            return new PublicKey(publicKeyMemory, keyIdentifier, verificationFunction);
        }

        /// <summary>
        /// Creates a private key object using the mapped signing function.
        /// </summary>
        public static PrivateKey CreatePrivateKey(
            PrivateKeyMemory privateKeyMemory,
            string keyIdentifier,
            Tag tag,
            string? selector = null)
        {
            if(SigningMapping == null)
            {
                throw new InvalidOperationException("Signing mapping has not been initialized.");
            }
            
            var signingFunction = SigningMapping(tag, selector) ?? throw new ArgumentException($"No signing function registered for {tag}, {selector}.");

            return new PrivateKey(privateKeyMemory, keyIdentifier, signingFunction);
        }
    }
}
