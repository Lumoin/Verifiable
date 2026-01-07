using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Did;

/// <summary>
/// Represents a reference to a verification method in a DID document or Data Integrity proof.
/// </summary>
/// <remarks>
/// <para>
/// A verification method reference can be either a URI string reference to a verification
/// method defined elsewhere, or an embedded verification method object included directly.
/// This polymorphism is defined in W3C Controlled Identifiers 1.0 §2.2.4.
/// </para>
/// <para>
/// <strong>Design Rationale:</strong>
/// </para>
/// <para>
/// The verification relationship types (<see cref="AuthenticationMethod"/>, <see cref="AssertionMethod"/>,
/// <see cref="KeyAgreementMethod"/>, <see cref="CapabilityInvocationMethod"/>, <see cref="CapabilityDelegationMethod"/>)
/// inherit from this abstract base class. The type hierarchy carries semantic meaning about the
/// purpose of the verification method reference:
/// </para>
/// <list type="bullet">
/// <item><description>
/// In <strong>DID documents</strong>, the purpose is determined by which property array the
/// reference appears in (e.g., <c>authentication</c>, <c>assertionMethod</c>).
/// </description></item>
/// <item><description>
/// In <strong>Data Integrity proofs</strong>, the purpose is explicit in the <c>proofPurpose</c>
/// property, and converters create the appropriate subclass based on that value.
/// </description></item>
/// </list>
/// <para>
/// Each subclass exposes its purpose string via the <see cref="PurposeName"/> property and
/// a static <c>Purpose</c> constant for use in converters and switch expressions.
/// </para>
/// <para>
/// <strong>Specification References:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see href="https://www.w3.org/TR/did-core/#verification-methods">DID Core §5.2 Verification Methods</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/did-core/#verification-relationships">DID Core §5.3 Verification Relationships</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/cid-1.0/#referring-to-verification-methods">CID 1.0 §2.2.4 Referring to Verification Methods</see>
/// </description></item>
/// <item><description>
/// <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">VC Data Integrity §4 Proofs</see>
/// </description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("VerificationMethodReference(Id = {Id}, Purpose = {PurposeName}, IsEmbedded = {IsEmbeddedVerification})")]
public abstract class VerificationMethodReference: IEquatable<VerificationMethodReference>
{
    /// <summary>
    /// Gets the URI reference to a verification method when not embedded.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This can be either a fragment reference (e.g., <c>#key-1</c>) that resolves
    /// within the same document, or an absolute DID URL (e.g., <c>did:example:123#key-1</c>)
    /// that may reference a verification method in another document.
    /// </para>
    /// <para>
    /// This property is mutually exclusive with <see cref="EmbeddedVerification"/>. When
    /// <see cref="IsEmbeddedVerification"/> is <c>false</c>, this property contains the reference.
    /// </para>
    /// </remarks>
    public string? VerificationReferenceId { get; }

    /// <summary>
    /// Gets the embedded verification method when included directly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When a verification method is embedded, its full definition is included
    /// directly rather than referenced by URI. Embedded methods can only be used
    /// for the specific verification relationship in which they appear.
    /// </para>
    /// <para>
    /// This property is mutually exclusive with <see cref="VerificationReferenceId"/>. When
    /// <see cref="IsEmbeddedVerification"/> is <c>true</c>, this property contains the method.
    /// </para>
    /// </remarks>
    public VerificationMethod? EmbeddedVerification { get; }

    /// <summary>
    /// Gets the verification method identifier, whether from a reference or embedded method.
    /// </summary>
    /// <remarks>
    /// This provides a unified way to access the identifier regardless of whether
    /// the verification method is referenced or embedded.
    /// </remarks>
    public string? Id => EmbeddedVerification?.Id ?? VerificationReferenceId;

    /// <summary>
    /// Gets a value indicating whether this contains an embedded verification method.
    /// </summary>
    public bool IsEmbeddedVerification => EmbeddedVerification is not null;

    /// <summary>
    /// Gets the verification purpose name as defined in the W3C specifications.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property returns the camelCase purpose string as defined in DID Core and
    /// Data Integrity specifications. The value is case-sensitive and must match exactly
    /// when used in JSON-LD documents.
    /// </para>
    /// <para>
    /// Purpose values are:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>authentication</c> - for <see cref="AuthenticationMethod"/></description></item>
    /// <item><description><c>assertionMethod</c> - for <see cref="AssertionMethod"/></description></item>
    /// <item><description><c>keyAgreement</c> - for <see cref="KeyAgreementMethod"/></description></item>
    /// <item><description><c>capabilityInvocation</c> - for <see cref="CapabilityInvocationMethod"/></description></item>
    /// <item><description><c>capabilityDelegation</c> - for <see cref="CapabilityDelegationMethod"/></description></item>
    /// </list>
    /// </remarks>
    public abstract string PurposeName { get; }


    /// <summary>
    /// Initializes a new instance with a URI reference to a verification method.
    /// </summary>
    /// <param name="verificationReferenceId">The URI reference to the verification method.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="verificationReferenceId"/> is <c>null</c>.</exception>
    protected VerificationMethodReference(string verificationReferenceId)
    {
        ArgumentNullException.ThrowIfNull(verificationReferenceId);
        VerificationReferenceId = verificationReferenceId;
    }


    /// <summary>
    /// Initializes a new instance with an embedded verification method.
    /// </summary>
    /// <param name="embeddedVerification">The embedded verification method.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="embeddedVerification"/> is <c>null</c>.</exception>
    protected VerificationMethodReference(VerificationMethod embeddedVerification)
    {
        ArgumentNullException.ThrowIfNull(embeddedVerification);
        EmbeddedVerification = embeddedVerification;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(VerificationMethodReference? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        //Different purpose types are not equal.
        if(GetType() != other.GetType())
        {
            return false;
        }

        return string.Equals(VerificationReferenceId, other.VerificationReferenceId, StringComparison.Ordinal)
            && Equals(EmbeddedVerification, other.EmbeddedVerification);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is VerificationMethodReference reference && Equals(reference);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(GetType());
        hash.Add(VerificationReferenceId, StringComparer.Ordinal);
        hash.Add(EmbeddedVerification);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="VerificationMethodReference"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if the instances are equal; otherwise, <c>false</c>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(VerificationMethodReference? left, VerificationMethodReference? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <summary>
    /// Determines whether two <see cref="VerificationMethodReference"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if the instances are not equal; otherwise, <c>false</c>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(VerificationMethodReference? left, VerificationMethodReference? right) =>
        !(left == right);
}