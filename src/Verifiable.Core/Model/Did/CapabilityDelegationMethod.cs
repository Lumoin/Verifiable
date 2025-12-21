using System.Diagnostics;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Represents a verification method reference used for capability delegation.
/// </summary>
/// <remarks>
/// <para>
/// The <c>capabilityDelegation</c> verification relationship is used to specify a
/// mechanism that might be used by the DID subject to delegate a cryptographic
/// capability to another party, such as delegating the ability to access a
/// specific resource or perform certain actions.
/// </para>
/// <para>
/// <strong>Usage Contexts:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>DID Documents</strong>: Appears in the <c>capabilityDelegation</c> array property.
/// </description></item>
/// <item><description>
/// <strong>Data Integrity Proofs</strong>: Created when <c>proofPurpose</c> is <c>"capabilityDelegation"</c>.
/// </description></item>
/// </list>
/// <para>
/// Example use cases include:
/// </para>
/// <list type="bullet">
/// <item><description>Delegating access rights to resources.</description></item>
/// <item><description>Granting temporary permissions to third parties.</description></item>
/// <item><description>Creating delegation chains in capability-based systems.</description></item>
/// <item><description>Authorizing agents to act on behalf of the DID subject.</description></item>
/// </list>
/// <para>
/// This relationship enables the creation of delegation hierarchies where the DID
/// subject can authorize others to perform specific actions or access specific
/// resources on their behalf.
/// </para>
/// <para>
/// <strong>Example JSON in DID Document:</strong>
/// </para>
/// <code>
/// {
///   "capabilityDelegation": [
///     "#key-1",
///     {
///       "id": "did:example:123#delegation-key",
///       "type": "JsonWebKey2020",
///       "controller": "did:example:123",
///       "publicKeyJwk": { ... }
///     }
///   ]
/// }
/// </code>
/// <para>
/// See <see href="https://www.w3.org/TR/cid-1.0/#capability-delegation">CID 1.0 §2.3.5 Capability Delegation</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("CapabilityDelegationMethod(Id = {Id}, IsEmbedded = {IsEmbeddedVerification})")]
public sealed class CapabilityDelegationMethod: VerificationMethodReference
{
    /// <summary>
    /// The verification purpose string as defined in W3C specifications.
    /// </summary>
    /// <remarks>
    /// This constant value is <c>"capabilityDelegation"</c> and is case-sensitive.
    /// Use this constant in converters and switch expressions to avoid magic strings.
    /// </remarks>
    public const string Purpose = "capabilityDelegation";

    /// <inheritdoc/>
    public override string PurposeName => Purpose;


    /// <summary>
    /// Initializes a new instance with a URI reference to a verification method.
    /// </summary>
    /// <param name="verificationReferenceId">
    /// The URI reference to the verification method. This can be a fragment reference
    /// (e.g., <c>#key-1</c>) or an absolute DID URL (e.g., <c>did:example:123#key-1</c>).
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="verificationReferenceId"/> is <c>null</c>.
    /// </exception>
    public CapabilityDelegationMethod(string verificationReferenceId): base(verificationReferenceId)
    {
    }


    /// <summary>
    /// Initializes a new instance with an embedded verification method.
    /// </summary>
    /// <param name="embeddedVerification">
    /// The embedded verification method. Embedded methods are defined inline within
    /// the verification relationship.
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="embeddedVerification"/> is <c>null</c>.
    /// </exception>
    public CapabilityDelegationMethod(VerificationMethod embeddedVerification): base(embeddedVerification)
    {
    }
}