using System.Linq;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class JsonWebKey2020VerificationMethod: VerificationMethodTypeInfo
    {
        public static JsonWebKey2020VerificationMethod Instance { get; } = new()
        {
            TypeName = "JsonWebKey2020",
            DefaultKeyFormatType = typeof(PublicKeyJwk),
            Contexts = new[] { "https://w3id.org/security/suites/jws-2020/v1" }.ToList().AsReadOnly()
        };
    }

    public sealed class Ed25519VerificationMethod:VerificationMethodTypeInfo
    {
        public static Ed25519VerificationMethod Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/ed25519-2020/v1" }.ToList().AsReadOnly()
        };
    }

    public sealed class Secp256k1VerificationMethod:VerificationMethodTypeInfo
    {
        public static Secp256k1VerificationMethod Instance { get; } = new()
        {
            TypeName = "Secp256k1VerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/secp256k1-2019/v1" }.ToList().AsReadOnly()
        };
    }

    public sealed class MultikeyVerificationMethod:VerificationMethodTypeInfo
    {
        public static MultikeyVerificationMethod Instance { get; } = new()
        {
            TypeName = "Multikey",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/multikey/v1" }.ToList().AsReadOnly()
        };
    }

    public sealed class X25519KeyAgreementKey2020VerificationMethod:VerificationMethodTypeInfo
    {
        public static X25519KeyAgreementKey2020VerificationMethod Instance { get; } = new()
        {
            TypeName = "X25519KeyAgreementKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/x25519-2020/v1" }.ToList().AsReadOnly()
        };
    }



#pragma warning disable CS0618 // Type or member is obsolete

    public sealed class X25519KeyAgreementKey2019VerificationMethod:VerificationMethodTypeInfo
    {
        public static X25519KeyAgreementKey2019VerificationMethod Instance { get; } = new()
        {
            TypeName = "X25519KeyAgreementKey2019",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),

            //TODO: this context here is wrong (and deprecated)!
            Contexts = new[] { "https://w3id.org/security/suites/x25519-2020/v1" }.ToList().AsReadOnly()
        };
    }
    public sealed class RsaVerificationMethod:VerificationMethodTypeInfo
    {
        public static RsaVerificationMethod Instance { get; } = new()
        {
            TypeName = "RsaVerificationKey2018",

            DefaultKeyFormatType = typeof(PublicKeyPem), // RSA keys often use PEM format

            Contexts = new[] { "https://w3id.org/security/suites/rsa-2018/v1" }.ToList().AsReadOnly(),
            CompatibleKeyFormats = new[] { typeof(PublicKeyPem), typeof(PublicKeyJwk) }.ToList().AsReadOnly()
        };
    }

    public sealed class JwsVerificationKey2020Method:VerificationMethodTypeInfo
    {
        public static JwsVerificationKey2020Method Instance { get; } = new()
        {
            TypeName = "JwsVerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyJwk),
            Contexts = new[] { "https://w3id.org/security/suites/jws-2020/v1" }.ToList().AsReadOnly()
        };
    }

    public sealed class Ed25519VerificationMethod2018:VerificationMethodTypeInfo
    {
        public static Ed25519VerificationMethod2018 Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyBase58), // 2018 version used Base58
            Contexts = new[] { "https://w3id.org/security/suites/ed25519-2018/v1" }.ToList().AsReadOnly(),
            CompatibleKeyFormats = new[] { typeof(PublicKeyBase58), typeof(PublicKeyMultibase) }.ToList().AsReadOnly()
        };
    }


    public static class VerificationMethodExtensions
    {
        extension(VerificationMethodTypeInfo)
        {
            public static JsonWebKey2020VerificationMethod JsonWebKey2020 => JsonWebKey2020VerificationMethod.Instance;
            public static Ed25519VerificationMethod Ed25519 => Ed25519VerificationMethod.Instance;
            public static Secp256k1VerificationMethod Secp256k1 => Secp256k1VerificationMethod.Instance;
            public static MultikeyVerificationMethod Multikey => MultikeyVerificationMethod.Instance;
            public static X25519KeyAgreementKey2020VerificationMethod X25519 => X25519KeyAgreementKey2020VerificationMethod.Instance;
            public static X25519KeyAgreementKey2019VerificationMethod X25519_2019 => X25519KeyAgreementKey2019VerificationMethod.Instance;
            public static RsaVerificationMethod Rsa => RsaVerificationMethod.Instance;
            public static JwsVerificationKey2020Method Jws => JwsVerificationKey2020Method.Instance;
            public static Ed25519VerificationMethod2018 Ed25519_2018 => Ed25519VerificationMethod2018.Instance;
        }
    }

#pragma warning restore CS0618 // Type or member is obsolete
}
