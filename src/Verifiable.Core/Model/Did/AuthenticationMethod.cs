using System.Diagnostics;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Represents a verification method reference authorized for authentication operations.
/// </summary>
/// <remarks>
/// <para>
/// The <c>authentication</c> verification relationship specifies which verification methods
/// can be used to authenticate as the DID subject. This is used for proving control of the DID,
/// such as logging into a website or authorizing access to a resource.
/// </para>
/// <para>
/// <strong>Usage Contexts:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>DID Documents</strong>: Appears in the <c>authentication</c> array property.
/// The JSON serializer creates this type when deserializing entries from that array.
/// </description></item>
/// <item><description>
/// <strong>Data Integrity Proofs</strong>: Created when <c>proofPurpose</c> is <c>"authentication"</c>.
/// Used when a proof demonstrates control of an identifier rather than making an assertion.
/// </description></item>
/// </list>
/// <para>
/// <strong>Example JSON in DID Document:</strong>
/// </para>
/// <code>
/// {
///   "authentication": [
///     "#key-1",
///     {
///       "id": "#key-2",
///       "type": "JsonWebKey2020",
///       "controller": "did:example:123",
///       "publicKeyJwk": { ... }
///     }
///   ]
/// }
/// </code>
/// <para>
/// <strong>Specification References:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see href="https://www.w3.org/TR/did-core/#authentication">DID Core §5.3.1 Authentication</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/cid-1.0/#authentication">CID 1.0 §2.3.1 Authentication</see>
/// </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("AuthenticationMethod(Id = {Id}, IsEmbedded = {IsEmbeddedVerification})")]
public sealed class AuthenticationMethod: VerificationMethodReference
{
    /// <summary>
    /// The verification purpose string as defined in W3C specifications.
    /// </summary>
    /// <remarks>
    /// This constant value is <c>"authentication"</c> and is case-sensitive.
    /// Use this constant in converters and switch expressions to avoid magic strings.
    /// </remarks>
    public const string Purpose = "authentication";

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
    public AuthenticationMethod(string verificationReferenceId): base(verificationReferenceId)
    {
    }


    /// <summary>
    /// Initializes a new instance with an embedded verification method.
    /// </summary>
    /// <param name="embeddedVerification">
    /// The embedded verification method. Embedded methods are defined inline within
    /// the verification relationship and can only be used for authentication.
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="embeddedVerification"/> is <c>null</c>.
    /// </exception>
    public AuthenticationMethod(VerificationMethod embeddedVerification): base(embeddedVerification)
    {
    }
}