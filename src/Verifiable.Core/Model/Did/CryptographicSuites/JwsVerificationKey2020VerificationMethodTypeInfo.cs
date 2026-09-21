namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// Verification method type descriptor for the obsolete <c>JwsVerificationKey2020</c>
    /// suite, whose default key material format is a <see cref="PublicKeyJwk"/> and whose
    /// context carries the <c>jws-2020</c> security suite IRI.
    /// </summary>
    public sealed class JwsVerificationKey2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        /// <summary>Gets the shared, immutable descriptor instance for <c>JwsVerificationKey2020</c>.</summary>
        public static JwsVerificationKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "JwsVerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyJwk),
            Contexts = new[] { "https://w3id.org/security/suites/jws-2020/v1" }.ToList().AsReadOnly()
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}
