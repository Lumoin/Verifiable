namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>Ed25519VerificationKey2018</c> verification method type: an Ed25519 public key encoded as
    /// <see cref="PublicKeyBase58"/>, per the Ed25519 Signature 2018 suite.
    /// </summary>
    public sealed class Ed25519VerificationKey2018VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        /// <summary>The shared <see cref="Ed25519VerificationKey2018VerificationMethodTypeInfo"/> instance.</summary>
        public static Ed25519VerificationKey2018VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyBase58),
            Contexts = new[] { "https://w3id.org/security/suites/ed25519-2018/v1" }.ToList().AsReadOnly()
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}
