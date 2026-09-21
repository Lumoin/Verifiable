namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>X25519KeyAgreementKey2020</c> verification method type: a Curve25519 key
    /// agreement public key expressed as multibase-encoded key material, per
    /// <see href="https://w3c-ccg.github.io/lds-jws2020/#x25519keyagreementkey2020">the
    /// Linked Data Cryptographic Suite Registry's x25519-2020 suite</see>.
    /// </summary>
    public sealed class X25519KeyAgreementKey2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        /// <summary>
        /// The singleton <c>X25519KeyAgreementKey2020</c> type info, carrying the type name,
        /// the multibase key format, and the suite's required JSON-LD context.
        /// </summary>
        public static X25519KeyAgreementKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "X25519KeyAgreementKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/x25519-2020/v1" }.ToList().AsReadOnly()
        };
    }
}
