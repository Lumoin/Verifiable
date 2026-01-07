using System.Diagnostics;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Represents a verification method reference authorized for key agreement operations.
/// </summary>
/// <remarks>
/// <para>
/// The <c>keyAgreement</c> verification relationship specifies which verification methods
/// can be used for key exchange protocols, such as establishing encrypted communication
/// channels using Elliptic Curve Diffie-Hellman (ECDH).
/// </para>
/// <para>
/// <strong>Usage Contexts:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>DID Documents</strong>: Appears in the <c>keyAgreement</c> array property.
/// The JSON serializer creates this type when deserializing entries from that array.
/// </description></item>
/// <item><description>
/// <strong>Data Integrity Proofs</strong>: Created when <c>proofPurpose</c> is <c>"keyAgreement"</c>.
/// Used in encrypted credential scenarios or establishing secure channels.
/// </description></item>
/// </list>
/// <para>
/// <strong>Supported Key Types:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>X25519 and X448 - Designed specifically for ECDH key agreement.</description></item>
/// <item><description>NIST P-curves (P-256, P-384, P-521) - When configured for key agreement.</description></item>
/// <item><description>secp256k1 - When configured for key agreement.</description></item>
/// <item><description>Ed25519 - Can be derived to X25519 for key agreement purposes.</description></item>
/// </list>
/// <para>
/// RSA keys typically do not support ECDH key agreement and should not use this relationship.
/// </para>
/// <para>
/// <strong>Example JSON in DID Document:</strong>
/// </para>
/// <code>
/// {
///   "keyAgreement": [
///     "#key-agreement-1",
///     {
///       "id": "#key-agreement-2",
///       "type": "X25519KeyAgreementKey2020",
///       "controller": "did:example:123",
///       "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
///     }
///   ]
/// }
/// </code>
/// <para>
/// <strong>Specification References:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see href="https://www.w3.org/TR/did-core/#key-agreement">DID Core §5.3.3 Key Agreement</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/cid-1.0/#key-agreement">CID 1.0 §2.3.3 Key Agreement</see>
/// </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("KeyAgreementMethod(Id = {Id}, IsEmbedded = {IsEmbeddedVerification})")]
public sealed class KeyAgreementMethod: VerificationMethodReference
{
    /// <summary>
    /// The verification purpose string as defined in W3C specifications.
    /// </summary>
    /// <remarks>
    /// This constant value is <c>"keyAgreement"</c> and is case-sensitive.
    /// Use this constant in converters and switch expressions to avoid magic strings.
    /// </remarks>
    public const string Purpose = "keyAgreement";

    /// <inheritdoc/>
    public override string PurposeName => Purpose;


    /// <summary>
    /// Initializes a new instance with a URI reference to a verification method.
    /// </summary>
    /// <param name="verificationReferenceId">
    /// The URI reference to the verification method. This can be a fragment reference
    /// (e.g., <c>#key-agreement-1</c>) or an absolute DID URL (e.g., <c>did:example:123#key-agreement-1</c>).
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="verificationReferenceId"/> is <c>null</c>.
    /// </exception>
    public KeyAgreementMethod(string verificationReferenceId)
        : base(verificationReferenceId)
    {
    }


    /// <summary>
    /// Initializes a new instance with an embedded verification method.
    /// </summary>
    /// <param name="embeddedVerification">
    /// The embedded verification method. Embedded methods are defined inline within
    /// the verification relationship and can only be used for key agreement.
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="embeddedVerification"/> is <c>null</c>.
    /// </exception>
    public KeyAgreementMethod(VerificationMethod embeddedVerification)
        : base(embeddedVerification)
    {
    }
}