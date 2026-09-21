namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>Bls12381G2Key2020</c> verification method type, keyed with a BLS12-381 G2 public key
    /// encoded as <see cref="PublicKeyMultibase"/>.
    /// </summary>
    public sealed class Bls12381G2VerificationMethodVerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        /// <summary>The singleton <see cref="Bls12381G2VerificationMethodVerificationMethodTypeInfo"/> instance.</summary>
        public static Bls12381G2VerificationMethodVerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Bls12381G2Key2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/bls12381-2020/v1" }.ToList().AsReadOnly()
        };
    }
}
