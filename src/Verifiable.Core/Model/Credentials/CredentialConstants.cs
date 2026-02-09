using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials
{
    /// <summary>
    /// Contains well-known constants for Verifiable Credentials including context URIs,
    /// type strings, and other standard values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These constants ensure consistency when creating and validating credentials,
    /// and help avoid typos in frequently used values.
    /// </para>
    /// </remarks>
    public static class CredentialConstants
    {
        /// <summary>
        /// The VC Data Model 2.0 base context URI.
        /// This must be the first context in any VC 2.0 credential or presentation.
        /// </summary>
        public const string CredentialsV2Context = "https://www.w3.org/ns/credentials/v2";

        /// <summary>
        /// Gets the default JSON-LD context for VC 2.0 credentials.
        /// This contains the base VC 2.0 context URI.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The VC 2.0 context is self-contained and includes definitions for Data Integrity
        /// proofs and common verification method types. Additional contexts can be added
        /// for credential-specific vocabulary.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">
        /// VC Data Model 2.0 §4.2 Contexts</see>.
        /// </para>
        /// </remarks>
        public static Context DefaultVc20Context { get; } = new Context
        {
            Contexts = [CredentialsV2Context]
        };

        /// <summary>
        /// The VC Data Model 1.1 base context URI.
        /// Used for backwards compatibility with VC 1.1 credentials.
        /// </summary>
        public const string CredentialsV1Context = "https://www.w3.org/2018/credentials/v1";

        /// <summary>
        /// The Data Integrity context URI for cryptographic proofs.
        /// </summary>
        public const string DataIntegrityContext = "https://w3id.org/security/data-integrity/v2";

        /// <summary>
        /// The Multikey context URI for Multikey verification methods.
        /// </summary>
        public const string MultikeyContext = "https://w3id.org/security/multikey/v1";

        /// <summary>
        /// The base type for all Verifiable Credentials.
        /// </summary>
        public const string VerifiableCredentialType = "VerifiableCredential";

        /// <summary>
        /// The base type for all Verifiable Presentations.
        /// </summary>
        public const string VerifiablePresentationType = "VerifiablePresentation";

        /// <summary>
        /// The type identifier for Data Integrity proofs.
        /// </summary>
        public const string DataIntegrityProofType = "DataIntegrityProof";


        /// <summary>
        /// Proof purposes as defined in the VC and DID specifications.
        /// </summary>
        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "These are nested on purpose.")]
        public static class ProofPurposes
        {
            /// <summary>
            /// Used when the proof is for making assertions or claims.
            /// Credentials are typically signed with this purpose.
            /// </summary>
            public const string AssertionMethod = "assertionMethod";

            /// <summary>
            /// Used when the proof is for authentication.
            /// Presentations are typically signed with this purpose.
            /// </summary>
            public const string Authentication = "authentication";

            /// <summary>
            /// Used when the proof is for invoking a capability.
            /// </summary>
            public const string CapabilityInvocation = "capabilityInvocation";

            /// <summary>
            /// Used when the proof is for delegating a capability.
            /// </summary>
            public const string CapabilityDelegation = "capabilityDelegation";

            /// <summary>
            /// Used when the proof is for key agreement.
            /// </summary>
            public const string KeyAgreement = "keyAgreement";
        }


        /// <summary>
        /// Well-known cryptosuite identifiers for Data Integrity proofs.
        /// </summary>

        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "These are nested on purpose.")]
        public static class Cryptosuites
        {
            /// <summary>
            /// EdDSA with RDFC-1.0 canonicalization (Ed25519).
            /// </summary>
            public const string EddsaRdfc2022 = "eddsa-rdfc-2022";

            /// <summary>
            /// EdDSA with JCS canonicalization (Ed25519).
            /// </summary>
            public const string EddsaJcs2022 = "eddsa-jcs-2022";

            /// <summary>
            /// ECDSA with RDFC-1.0 canonicalization (P-256, P-384).
            /// </summary>
            public const string EcdsaRdfc2019 = "ecdsa-rdfc-2019";

            /// <summary>
            /// ECDSA with JCS canonicalization (P-256, P-384).
            /// </summary>
            public const string EcdsaJcs2019 = "ecdsa-jcs-2019";

            /// <summary>
            /// ECDSA selective disclosure with RDFC-1.0 canonicalization.
            /// </summary>
            public const string EcdsaSd2023 = "ecdsa-sd-2023";

            /// <summary>
            /// BBS selective disclosure.
            /// </summary>
            public const string Bbs2023 = "bbs-2023";
        }


        /// <summary>
        /// Status types for credential revocation and suspension.
        /// </summary>
        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "These are nested on purpose.")]
        public static class StatusTypes
        {
            /// <summary>
            /// Bitstring status list entry for efficient status checking.
            /// </summary>
            public const string BitstringStatusListEntry = "BitstringStatusListEntry";

            /// <summary>
            /// Bitstring status list credential containing status entries.
            /// </summary>
            public const string BitstringStatusListCredential = "BitstringStatusListCredential";
        }


        /// <summary>
        /// Status purposes for credential status mechanisms.
        /// </summary>
        [SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "These are nested on purpose.")]
        public static class StatusPurposes
        {
            /// <summary>
            /// The credential has been permanently revoked.
            /// </summary>
            public const string Revocation = "revocation";

            /// <summary>
            /// The credential has been temporarily suspended.
            /// </summary>
            public const string Suspension = "suspension";
        }
    }
}