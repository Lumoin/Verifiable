using System.Diagnostics;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Represents a verification method reference authorized for making assertions or claims.
/// </summary>
/// <remarks>
/// <para>
/// The <c>assertionMethod</c> verification relationship specifies which verification methods
/// can be used to express claims, such as when issuing Verifiable Credentials. This is the
/// most common proof purpose for credential issuance.
/// </para>
/// <para>
/// <strong>Usage Contexts:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>DID Documents</strong>: Appears in the <c>assertionMethod</c> array property.
/// The JSON serializer creates this type when deserializing entries from that array.
/// </description></item>
/// <item><description>
/// <strong>Data Integrity Proofs</strong>: Created when <c>proofPurpose</c> is <c>"assertionMethod"</c>.
/// This is the standard proof purpose for Verifiable Credential issuance.
/// </description></item>
/// </list>
/// <para>
/// <strong>Example JSON in DID Document:</strong>
/// </para>
/// <code>
/// {
///   "assertionMethod": [
///     "#key-1",
///     "did:example:123#key-2"
///   ]
/// }
/// </code>
/// <para>
/// <strong>Example in Data Integrity Proof:</strong>
/// </para>
/// <code>
/// {
///   "type": "DataIntegrityProof",
///   "cryptosuite": "eddsa-rdfc-2022",
///   "verificationMethod": "did:example:issuer#key-1",
///   "proofPurpose": "assertionMethod",
///   "proofValue": "z..."
/// }
/// </code>
/// <para>
/// <strong>Specification References:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see href="https://www.w3.org/TR/did-core/#assertion">DID Core §5.3.2 Assertion</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/cid-1.0/#assertion">CID 1.0 §2.3.2 Assertion</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/vc-data-integrity/#proof-purposes">VC Data Integrity §4.1 Proof Purposes</see>
/// </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("AssertionMethod(Id = {Id}, IsEmbedded = {IsEmbeddedVerification})")]
public sealed class AssertionMethod: VerificationMethodReference
{
    /// <summary>
    /// The verification purpose string as defined in W3C specifications.
    /// </summary>
    /// <remarks>
    /// This constant value is <c>"assertionMethod"</c> and is case-sensitive.
    /// Use this constant in converters and switch expressions to avoid magic strings.
    /// </remarks>
    public const string Purpose = "assertionMethod";

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
    public AssertionMethod(string verificationReferenceId): base(verificationReferenceId)
    {
    }


    /// <summary>
    /// Initializes a new instance with an embedded verification method.
    /// </summary>
    /// <param name="embeddedVerification">
    /// The embedded verification method. Embedded methods are defined inline within
    /// the verification relationship and can only be used for assertions.
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="embeddedVerification"/> is <c>null</c>.
    /// </exception>
    public AssertionMethod(VerificationMethod embeddedVerification): base(embeddedVerification)
    {
    }
}