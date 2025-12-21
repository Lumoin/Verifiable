using System.Linq;

namespace Verifiable.Core.Model.Did
{
    public sealed class JsonWebSignature2020Proof: ProofTypeInfo
    {
        public static JsonWebSignature2020Proof Instance { get; } = new()
        {
            TypeName = "JsonWebSignature2020",
            Contexts = new[] { "https://w3id.org/security/suites/jws-2020/v1" }.ToList().AsReadOnly(),
            IsCompatibleWith = vm => vm.TypeName == JsonWebKey2020VerificationMethodTypeInfo.Instance.TypeName ||
                                    vm.TypeName == RsaVerificationKey2018VerificationMethodTypeInfo.Instance.TypeName
        };
    }

    public sealed class DataIntegrityProofType: ProofTypeInfo
    {
        public static DataIntegrityProofType Instance { get; } = new()
        {
            TypeName = "DataIntegrityProof",
            Contexts = new[] { "https://w3id.org/security/data-integrity/v1" }.ToList().AsReadOnly(),
            IsCompatibleWith = vm => vm.TypeName == MultikeyVerificationMethodTypeInfo.Instance.TypeName ||
                                    vm.TypeName == Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance.TypeName ||
                                    vm.TypeName == JsonWebKey2020VerificationMethodTypeInfo.Instance.TypeName
        };
    }

    public sealed class Ed25519Signature2020Proof: ProofTypeInfo
    {
        public static Ed25519Signature2020Proof Instance { get; } = new()
        {
            TypeName = "Ed25519Signature2020",
            Contexts = new[] { "https://w3id.org/security/suites/ed25519-2020/v1" }.ToList().AsReadOnly(),
            IsCompatibleWith = vm => vm.TypeName == Ed25519VerificationKey2020VerificationMethodTypeInfo.Instance.TypeName ||
                                    vm.TypeName == MultikeyVerificationMethodTypeInfo.Instance.TypeName
        };
    }

    public sealed class EcdsaSecp256k1Signature2019Proof: ProofTypeInfo
    {
        public static EcdsaSecp256k1Signature2019Proof Instance { get; } = new()
        {
            TypeName = "EcdsaSecp256k1Signature2019",
            Contexts = new[] { "https://w3id.org/security/suites/secp256k1-2019/v1" }.ToList().AsReadOnly(),
            IsCompatibleWith = vm => vm.TypeName == Secp256k1VerificationKey2018MethodTypeInfo.Instance.TypeName ||
                                    vm.TypeName == MultikeyVerificationMethodTypeInfo.Instance.TypeName
        };
    }

    public sealed class BbsBlsSignature2020Proof: ProofTypeInfo
    {
        public static BbsBlsSignature2020Proof Instance { get; } = new()
        {
            TypeName = "BbsBlsSignature2020",
            Contexts = new[] { "https://w3id.org/security/bbs/v1" }.ToList().AsReadOnly(),
            IsCompatibleWith = vm => vm.TypeName == Bls12381G2VerificationMethodVerificationMethodTypeInfo.Instance.TypeName
        };
    }

    public static class ProofTypeExtensions
    {
        extension(ProofTypeInfo)
        {
            public static JsonWebSignature2020Proof JsonWebSignature2020 => JsonWebSignature2020Proof.Instance;
            public static DataIntegrityProofType DataIntegrityProof => DataIntegrityProofType.Instance;
            public static Ed25519Signature2020Proof Ed25519Signature2020 => Ed25519Signature2020Proof.Instance;
            public static EcdsaSecp256k1Signature2019Proof EcdsaSecp256k1Signature2019 => EcdsaSecp256k1Signature2019Proof.Instance;
            public static BbsBlsSignature2020Proof BbsBlsSignature2020 => BbsBlsSignature2020Proof.Instance;
        }
    }
}