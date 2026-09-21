namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>Secp256k1VerificationKey2018</c> verification method type: a secp256k1 public key encoded as
    /// <see cref="PublicKeyMultibase"/>.
    /// </summary>
    public sealed class Secp256k1VerificationKey2018MethodTypeInfo: VerificationMethodTypeInfo
    {
        /// <summary>The shared <see cref="Secp256k1VerificationKey2018MethodTypeInfo"/> instance.</summary>
        public static Secp256k1VerificationKey2018MethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Secp256k1VerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/secp256k1-2019/v1" }.ToList().AsReadOnly()
        };
    }
}
