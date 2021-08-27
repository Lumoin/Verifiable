namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#key-types-and-formats
    /// </summary>
    public static class DidCoreKeyTypes
    {
        public const string RsaVerificationKey2018 = "rsaVerificationKey2018";
        public const string Ed25519VerificationKey2018 = "ed25519VerificationKey2018";
        public const string SchnorrSecp256k1VerificationKey2019 = "schnorrSecp256k1VerificationKey2019";
        public const string X25519KeyAgreementKey2019 = "x25519KeyAgreementKey2019";
    }


    /// <summary>
    /// Constants for various cryptographic algorithms used in
    /// decentralized identifiers and verifiable credentials.
    /// </summary>
    public static class CryptographyAlgorithmConstants
    {
        /// <summary>
        /// ECDH constants.
        /// </summary>
        public static class Ecdh
        {
            /// <summary>
            /// By definition, see at <see href="https://tools.ietf.org/html/rfc8037#section-2"/>.
            /// </summary>
            public const string KeyType = "OKP";

            /// <summary>
            /// By definition, see at <see href="https://tools.ietf.org/html/rfc8032#section-5.1.5"/>.
            /// </summary>
            public const int KeySizeInBytes = 32;

            public static class EdDsa
            {
                public const string Algorithm = "EdDSA";

                /// <summary>
                /// EdDSA key curves.
                /// </summary>
                public static class Curves
                {
                    //TODO: Add links to definitions as linked in https://tools.ietf.org/html/rfc8037#page-7.
                    public const string Ed25519 = "Ed25519";
                    public const string Ed448 = "Ed448";
                }
            }


            // https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2
            public static class EcdhEs
            {
                //https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
                public static class Curves
                {
                    public const string X25519 = "X25519";
                    public const string X448 = "X448";
                }
            }
        }
    }


    //TODO: These not as nameof-attributes since in the specification they start with
    //small letter while capital letter is a .NET convention.
    /// <summary>
    /// https://www.w3.org/TR/did-spec-registries/#verification-method-types
    /// </summary>
    public static class DidRegisteredKeyTypes
    {
        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#jwsverificationkey2020
        /// </summary>
        public const string JwsVerificationKey2020 = "jwsVerificationKey2020";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#ecdsasecp256k1verificationkey2019
        /// </summary>
        public const string EcdsaSecp256k1VerificationKey2019 = "ecdsaSecp256k1VerificationKey2019";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#ed25519verificationkey2018
        /// </summary>
        public const string Ed25519VerificationKey2018 = "ed25519VerificationKey2018";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#gpgverificationkey2020
        /// </summary>
        public const string GpgVerificationKey2020 = "gpgVerificationKey2020";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#rsaverificationkey2018
        /// </summary>
        public const string RsaVerificationKey2018 = "rsaVerificationKey2018";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#x25519keyagreementkey2019
        /// </summary>
        public const string X25519KeyAgreementKey2019 = "x25519KeyAgreementKey2019";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#ecdsasecp256k1recoverymethod2020
        /// </summary>
        public const string EcdsaSecp256k1RecoveryMethod2020 = "ecdsaSecp256k1RecoveryMethod2020";
    }


    /// <summary>
    /// This class holds some general constants as specified by DID Core specification.
    /// </summary>
    public static class DidCoreConstants
    {
        /// <summary>
        /// The DID documents must have a @context part in which the first URI is this.
        /// </summary>
        public const string JsonLdContextFirstUri = "https://www.w3.org/ns/did/v1";
    }
}
