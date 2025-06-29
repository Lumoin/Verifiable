namespace Verifiable.Core.Did.CryptographicSuites
{
    public static class CryptoSuiteExtensions
    {
        extension(CryptographicSuite)
        {
            public static Undefined Undefined => Undefined.Instance;
            public static JsonWebKey2020 JsonWebKey2020 => JsonWebKey2020.Instance;
            public static Ed25519VerificationKey2020 Ed25519VerificationKey2020 => Ed25519VerificationKey2020.Instance;
            public static Multikey Multikey => Multikey.Instance;
            public static Secp256k1VerificationKey2018 Secp256k1 => Secp256k1VerificationKey2018.Instance;
            public static RsaVerificationKey2018 RsaVerificationKey2018 => RsaVerificationKey2018.Instance;
            public static JwsVerificationKey2020 JwsVerificationKey2020 => JwsVerificationKey2020.Instance;
            public static Ed25519VerificationKey2018 Ed25519VerificationKey2018 => Ed25519VerificationKey2018.Instance;
            public static X25519KeyAgreementKey2019 X25519KeyAgreementKey2019 => X25519KeyAgreementKey2019.Instance;
        }
    }
}
