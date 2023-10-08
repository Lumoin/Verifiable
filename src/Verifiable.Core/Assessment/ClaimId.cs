using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Assessment
{
    /// <summary>
    /// Represents a unique identifier for a claim generated from a specific check that either succeeds or fails.
    /// <see cref="ClaimId"/> acts as a bridge between code and operational aspects like Security Development Operations (SecDevOps)
    /// and monitoring, facilitating tight integration and real-time feedback loops. It ties claim results to distributed tracing
    /// and telemetry for technical analysis and debugging, with an option to archive claims for later analysis or evidence using
    /// e.g., <see cref="ArchiveDelegateAsync"/>.
    /// </summary>
    /// <remarks>
    /// <para>Negative values are not allowed. Code <c>0</c> is reserved for <see cref="FailedClaim"/>.</para>
    /// <see cref="ClaimId"/> enables:
    /// <list type="bullet">
    /// <item>
    /// <description>Binding claim checks to code via <see cref="ClaimIssuer{TInput}"/>, which holds delegates to issue claims in <see cref="ClaimIssueResult"/>. Claims are then assessed by <see cref="ClaimAssessor{TInput}"/> to determine the overall case success or failure.</description>
    /// </item>
    /// <item>
    /// <description>Mapping claim identifiers to monitoring and SecDevOps tools, aligning with Forrester-recommended practices for a comprehensive view of system security and reliability.</description>
    /// </item>
    /// </list>
    /// This struct is lightweight and optimized for performance, minimizing overhead in collections or other data structures. 
    /// <see cref="ClaimId"/> supports dynamic extension of claim identifiers, adapting to evolving system requirements.
    /// </remarks>
    /// <example>
    /// Creating a new <see cref="ClaimId"/>:
    /// <code>
    /// var newClaimId = ClaimId2.Create(509);
    /// </code>
    /// </example>    
    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    public readonly struct ClaimId
    {                
        /// <summary>
        /// Gets the code representing the claim identifier.
        /// </summary>
        public int Code { get; }

        /// <summary>
        /// A marker for a failed claim.
        /// </summary>
        public static ClaimId FailedClaim { get; } = new(0, "FailedToGenerateClaims");

        /// <summary>
        /// Represents a claim for missing elliptic curve.
        /// </summary>
        public static ClaimId EcMissingCurve { get; } = new ClaimId(1, "EcMissingCurve");

        /// <summary>
        /// Represents a claim for missing X coordinate of an elliptic curve.
        /// </summary>
        public static ClaimId EcMissingXCoordinate { get; } = new ClaimId(2, "EcMissingXCoordinate");

        /// <summary>
        /// Represents a claim for missing Y coordinate of an elliptic curve.
        /// </summary>
        public static ClaimId EcMissingYCoordinate { get; } = new ClaimId(3, "EcMissingYCoordinate");

        /// <summary>
        /// Represents a claim for a valid algorithm and curve combination for elliptic curve.
        /// </summary>
        public static ClaimId EcValidAlgAndCrvCombination { get; } = new ClaimId(4, "EcValidAlgAndCrvCombination");
        
        /// <summary>
        /// Represents a claim for an algorithm that is optional and not present or empty for elliptic curve.
        /// </summary>
        public static ClaimId EcAlgOptionalAndNotPresentOrEmpty { get; } = new ClaimId(6, "EcAlgOptionalAndNotPresentOrEmpty");

        /// <summary>
        /// Represents a claim for a non-existing algorithm.
        /// </summary>
        public static ClaimId AlgNotExist { get; } = new ClaimId(7, "AlgNotExist");

        /// <summary>
        /// Represents a claim for an algorithm that is None.
        /// </summary>
        public static ClaimId AlgIsNone { get; } = new ClaimId(8, "AlgIsNone");

        /// <summary>
        /// Represents a claim for a valid algorithm.
        /// </summary>
        public static ClaimId AlgIsValid { get; } = new ClaimId(9, "AlgIsValid");

        // For ValidateKeyHeaders
        /// <summary>
        /// Represents a claim for missing or empty key type.
        /// </summary>
        public static ClaimId KtyMissingOrEmpty { get; } = new ClaimId(10, "KtyMissingOrEmpty");

        /// <summary>
        /// Represents a claim for EC key type.
        /// </summary>
        public static ClaimId EcKeyType { get; } = new ClaimId(11, "EcKeyType");

        /// <summary>
        /// Represents a claim for RSA key type.
        /// </summary>
        public static ClaimId RsaKeyType { get; } = new ClaimId(12, "RsaKeyType");

        /// <summary>
        /// Represents a claim for OCT key type (placeholder, in case you add more logic for 'oct').
        /// </summary>
        public static ClaimId OctKeyType { get; } = new ClaimId(13, "OctKeyType");

        /// <summary>
        /// Represents a claim for OKP key type.
        /// </summary>
        public static ClaimId OkpKeyType { get; } = new ClaimId(14, "OkpKeyType");

        /// <summary>
        /// Represents a claim for an unsupported key type.
        /// </summary>
        public static ClaimId UnsupportedKeyType { get; } = new ClaimId(15, "UnsupportedKeyType");

        // For ValidateRsa
        /// <summary>
        /// Represents a claim for missing RSA exponent.
        /// </summary>
        public static ClaimId RsaMissingExponent { get; } = new ClaimId(100, "RsaMissingExponent");

        /// <summary>
        /// Represents a claim for missing RSA modulus.
        /// </summary>
        public static ClaimId RsaMissingModulus { get; } = new ClaimId(101, "RsaMissingModulus");

        /// <summary>
        /// Represents a claim for a valid RSA key.
        /// </summary>
        public static ClaimId RsaKeyValid { get; } = new ClaimId(102, "RsaKeyValid");

        /// <summary>
        /// Represents a claim for an invalid RSA key.
        /// </summary>
        public static ClaimId RsaKeyInvalid { get; } = new ClaimId(103, "RsaKeyInvalid");

        // For ValidateOkp
        /// <summary>
        /// Represents a claim for missing OKP curve.
        /// </summary>
        public static ClaimId OkpMissingCurve { get; } = new ClaimId(200, "OkpMissingCurve");

        /// <summary>
        /// Represents a claim indicating that algorithm should not be present for X25519.
        /// </summary>
        public static ClaimId OkpAlgShouldNotBePresentForX25519 { get; } = new ClaimId(201, "OkpAlgShouldNotBePresentForX25519");

        /// <summary>
        /// Represents a claim for a valid algorithm and curve combination.
        /// </summary>
        public static ClaimId OkpValidAlgAndCrvCombination { get; } = new ClaimId(202, "OkpValidAlgAndCrvCombination");
        
        /// <summary>
        /// Represents a claim indicating that algorithm is optional or not present.
        /// </summary>
        public static ClaimId OkpAlgOptionalOrNotPresent { get; } = new ClaimId(204, "OkpAlgOptionalOrNotPresent");

        // For DID Core Validation
        /// <summary>
        /// Represents a claim for JSON-LD URI appearing first in DID Core validation.
        /// </summary>
        public static ClaimId DidCoreJsonLdUriAsFirst { get; } = new ClaimId(300, "DidCoreJsonLdUriAsFirst");

        // For DID Document Validation Rules
        /// <summary>
        /// Represents a claim for DID document prefix.
        /// </summary>
        public static ClaimId DidDocumentPrefix { get; } = new ClaimId(400, "DidDocumentPrefix");

        // For KeyDidValidationRules
        /// <summary>
        /// Represents a claim for Key DID prefix.
        /// </summary>
        public static ClaimId KeyDidPrefix { get; } = new ClaimId(500, "KeyDidPrefix");

        /// <summary>
        /// Represents a claim for Key DID ID encoding.
        /// </summary>
        public static ClaimId KeyDidIdEncoding { get; } = new ClaimId(501, "KeyDidIdEncoding");

        /// <summary>
        /// Represents a claim for Key DID ID format.
        /// </summary>        
        public static ClaimId KeyDidIdFormat { get; } = new ClaimId(502, "KeyDidIdFormat");

        /// <summary>
        /// Represents a claim for Key DID single verification method.
        /// </summary>
        public static ClaimId KeyDidSingleVerificationMethod { get; } = new ClaimId(503, "KeyDidSingleVerificationMethod");

        /// <summary>
        /// Represents a claim for Key DID key format.
        /// </summary>
        public static ClaimId KeyDidKeyFormat { get; } = new ClaimId(504, "KeyDidKeyFormat");

        /// <summary>
        /// Represents a claim for Key DID ID prefix match.
        /// </summary>
        public static ClaimId KeyDidIdPrefixMatch { get; } = new ClaimId(505, "KeyDidIdPrefixMatch");

        /// <summary>
        /// Represents a claim for Key DID ID prefix mismatch.
        /// </summary>        
        public static ClaimId KeyDidIdPrefixMismatch { get; } = new ClaimId(506, "KeyDidIdPrefixMismatch");

        /// <summary>
        /// Represents a claim for Key DID ID prefix missing.
        /// </summary>
        public static ClaimId KeyDidIdPrefixMissing { get; } = new ClaimId(507, "KeyDidIdPrefixMissing");

        /// <summary>
        /// Represents a claim for Key DID fragment identifier repetition.
        /// </summary>
        public static ClaimId KeyDidFragmentIdentifierRepetition { get; } = new ClaimId(508, "KeyDidFragmentIdentifierRepetition");


        /// <summary>
        /// Creates a new claim identifier.
        /// </summary>
        /// <param name="code">The code representing the claim identifier.</param>
        /// <param name="description">The description of the claim. Defaults to an empty string.</param>
        /// <returns>A new instance of <see cref="ClaimId"/>.</returns>
        public static ClaimId Create(int code, string description)
        {
            //At the moment only FailedClaimId is allowed to have code 0.
            //There are no negative codes. This should simplify storage.
            if(code <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(code), code, $"Value must be greater than zero.");
            }

            ArgumentException.ThrowIfNullOrEmpty(description, nameof(description));

            if(CodeDescriptions.Descriptions.ContainsKey(code))
            {
                throw new ArgumentException($"A {nameof(ClaimId)} with code {code} already exists.");
            }

            return new ClaimId(code, description);
        }


        /// <summary>
        /// Creating <see cref="ClaimId"/> without <see cref="Code"/> is not allowed.
        /// </summary>
        /// <exception cref="InvalidOperationException" />
        public ClaimId()
        {
            throw new InvalidOperationException($"Use {nameof(Create)}.");
        }


        /// <summary>
        /// Returns the string representation of the claim identifier, which includes the description of the claim.
        /// </summary>
        /// <returns>The string representation of the claim identifier.</returns>
        public override string ToString()
        {
            return CodeDescriptions.GetDescription(this);
        }


        private ClaimId(int code, string description)
        {
            Code = code;
            CodeDescriptions.AddDescription(code, description);
        }


        /// <summary>
        /// Explicitly called in DebuggerDisplay attribute to avoid calling ToString() on a struct.
        /// </summary>
        private string DebuggerDisplay => ToString();


        /// <summary>
        /// Descriptions for the library provided and dynamically created claim identifier codes.
        /// </summary>
        private static class CodeDescriptions
        {
            private static readonly object descriptionsLock = new object();

            /// <summary>
            /// Descriptions of dynamically created claim identifiers.
            /// </summary>
            public static Dictionary<int, string> Descriptions { get; } = new();


            /// <summary>
            /// Adds a description for a claim identifier.
            /// </summary>
            /// <param name="code">The identifier code.</param>
            /// <param name="description">The description of the claim identifier, or a default message for unknown identifiers.</param>
            public static void AddDescription(int code, string description)
            {
                lock(descriptionsLock)
                {
                    Descriptions.Add(code, description);
                }
            }


            /// <summary>
            /// Fetches the description of a claim identifier.
            /// </summary>
            /// <param name="claimId">The claim identifier.</param>
            /// <returns>The description of the claim identifier, or a default message for unknown identifiers.</returns>
            public static string GetDescription(ClaimId claimId)
            {
                lock(descriptionsLock)
                {
                    return Descriptions.TryGetValue(claimId.Code, out string? description) ? description : $"Unknown claim ID: {claimId.Code}";
                }
            }
        }
    }
}
