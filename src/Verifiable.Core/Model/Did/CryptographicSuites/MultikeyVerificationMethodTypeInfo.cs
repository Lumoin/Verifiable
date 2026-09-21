namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>Multikey</c> verification method type, per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#multikey">VC Data Integrity, Multikey</see>: a
    /// single multibase-encoded, multicodec-prefixed key covering every supported algorithm.
    /// </summary>
    public sealed class MultikeyVerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        /// <summary>The shared <c>Multikey</c> type-info singleton.</summary>
        public static MultikeyVerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Multikey",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/multikey/v1" }.ToList().AsReadOnly()
        };
    }
}
