namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>X25519KeyAgreementKey2019</c> verification method type: a Curve25519 key
    /// agreement public key expressed as multibase-encoded key material, per the Linked
    /// Data Cryptographic Suite Registry's x25519-2019 suite.
    /// </summary>
    public sealed class X25519KeyAgreementKey2019VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        /// <summary>The shared <see cref="X25519KeyAgreementKey2019VerificationMethodTypeInfo"/> instance.</summary>
        public static X25519KeyAgreementKey2019VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "X25519KeyAgreementKey2019",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            //TODO: this context here is wrong (and deprecated)!
            Contexts = new[] { "https://ns.did.ai/suites/x25519-2019/v1/" }.ToList().AsReadOnly()
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}
