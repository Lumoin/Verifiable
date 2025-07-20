using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Core.Did
{
    /// <remarks>
    /// <para>
    /// This extension class allows accessing verification method type instances using a clean, discoverable syntax
    /// directly on the <see cref="VerificationMethodTypeInfo"/> type. Instead of accessing instances through
    /// their concrete class names, users can access them through the base type with IntelliSense support.
    /// </para>
    /// <para>
    /// <strong>Usage:</strong>
    /// </para>
    /// <code>
    /// //Instead of: <c>JsonWebKey2020VerificationMethodTypeInfo.Instance</c>
    /// var jwkMethod = VerificationMethodTypeInfo.JsonWebKey2020;
    ///
    /// //Instead of: <c>Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance</c>
    /// var ed25519Method = VerificationMethodTypeInfo.Ed25519VerificationKey2020;
    /// </code>
    /// <para>
    /// <strong>Extensibility:</strong>
    /// </para>
    /// <para>
    /// Library users can define their own verification method extensions following the same pattern:
    /// </para>
    /// <code>
    /// public static class MyVerificationMethodExtensions
    /// {
    ///     extension(VerificationMethodTypeInfo)
    ///     {
    ///         public static MyVerificationMethodTypeInfo MyMethod => MyVerificationMethodTypeInfo.Instance;
    ///     }
    /// }
    /// </code>
    /// <para>
    /// After defining such an extension, <c>VerificationMethodTypeInfo.MyMethod</c> becomes available
    /// alongside the library-provided verification methods, maintaining consistency in the API.
    /// </para>
    /// <para>
    /// This pattern provides discoverability through IntelliSense while maintaining type safety and
    /// allowing seamless integration of custom verification method types.
    /// </para>
    /// </remarks>
    public static class VerificationMethodTypeInfoExtensions
    {
        extension(VerificationMethodTypeInfo)
        {
            public static JsonWebKey2020VerificationMethodTypeInfo JsonWebKey2020 => JsonWebKey2020VerificationMethodTypeInfo.Instance;
            public static Ed25519VerificationKey2020VerificationMethodTypeInfo Ed25519VerificationKey2020 => Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance;
            public static Secp256k1VerificationKey2018MethodTypeInfo Secp256k1VerificationKey2018 => Secp256k1VerificationKey2018MethodTypeInfo.Instance;
            public static MultikeyVerificationMethodTypeInfo Multikey => MultikeyVerificationMethodTypeInfo.Instance;
            public static X25519KeyAgreementKey2020VerificationMethodTypeInfo X25519KeyAgreementKey2020 => X25519KeyAgreementKey2020VerificationMethodTypeInfo.Instance;
            public static X25519KeyAgreementKey2019VerificationMethodTypeInfo X25519KeyAgreementKey2019 => X25519KeyAgreementKey2019VerificationMethodTypeInfo.Instance;
            public static RsaVerificationKey2018VerificationMethodTypeInfo RsaVerificationKey2018 => RsaVerificationKey2018VerificationMethodTypeInfo.Instance;
            public static JwsVerificationKey2020VerificationMethodTypeInfo JwsVerificationKey2020 => JwsVerificationKey2020VerificationMethodTypeInfo.Instance;
            public static Ed25519VerificationKey2018VerificationMethodTypeInfo Ed25519VerificationKey2018 => Ed25519VerificationKey2018VerificationMethodTypeInfo.Instance;
            public static UndefinedMethodTypeInfo Undefined => UndefinedMethodTypeInfo.Instance;
            public static Bls12381G2VerificationMethodVerificationMethodTypeInfo Bls12381G2 => Bls12381G2VerificationMethodVerificationMethodTypeInfo.Instance;
        }
    }
}
