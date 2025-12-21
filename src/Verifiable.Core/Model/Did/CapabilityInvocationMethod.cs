using System.Diagnostics;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Represents a verification method reference used for capability invocation.
/// </summary>
/// <remarks>
/// <para>
/// The <c>capabilityInvocation</c> verification relationship is used to specify a
/// verification method that might be used by the DID subject to invoke a cryptographic
/// capability, such as the authorization to update the DID document itself.
/// </para>
/// <para>
/// <strong>Usage Contexts:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>DID Documents</strong>: Appears in the <c>capabilityInvocation</c> array property.
/// </description></item>
/// <item><description>
/// <strong>Data Integrity Proofs</strong>: Created when <c>proofPurpose</c> is <c>"capabilityInvocation"</c>.
/// </description></item>
/// </list>
/// <para>
/// Example use cases include:
/// </para>
/// <list type="bullet">
/// <item><description>Authorizing updates to the DID document.</description></item>
/// <item><description>Invoking access control capabilities.</description></item>
/// <item><description>Exercising delegated permissions.</description></item>
/// <item><description>Authorizing resource access in capability-based systems.</description></item>
/// </list>
/// <para>
/// This relationship is particularly important for DID document management, as it
/// defines which keys are authorized to make changes to the DID document when
/// interacting with the DID method's update mechanisms.
/// </para>
/// <para>
/// <strong>Example JSON in DID Document:</strong>
/// </para>
/// <code>
/// {
///   "capabilityInvocation": [
///     "#key-1",
///     {
///       "id": "did:example:123#admin-key",
///       "type": "JsonWebKey2020",
///       "controller": "did:example:123",
///       "publicKeyJwk": { ... }
///     }
///   ]
/// }
/// </code>
/// <para>
/// See <see href="https://www.w3.org/TR/cid-1.0/#capability-invocation">CID 1.0 §2.3.4 Capability Invocation</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("CapabilityInvocationMethod(Id = {Id}, IsEmbedded = {IsEmbeddedVerification})")]
public sealed class CapabilityInvocationMethod: VerificationMethodReference
{
    /// <summary>
    /// The verification purpose string as defined in W3C specifications.
    /// </summary>
    /// <remarks>
    /// This constant value is <c>"capabilityInvocation"</c> and is case-sensitive.
    /// Use this constant in converters and switch expressions to avoid magic strings.
    /// </remarks>
    public const string Purpose = "capabilityInvocation";

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
    public CapabilityInvocationMethod(string verificationReferenceId): base(verificationReferenceId)
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
    public CapabilityInvocationMethod(VerificationMethod embeddedVerification): base(embeddedVerification)
    {
    }
}