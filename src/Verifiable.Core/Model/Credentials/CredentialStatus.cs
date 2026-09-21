using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.StatusLists;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents status information for a Verifiable Credential as defined in the W3C
/// Verifiable Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// The credential status mechanism enables verifiers to check whether a credential
/// has been revoked or suspended by the issuer after issuance. This allows issuers
/// to update the status of issued credentials without reissuing them.
/// </para>
/// <para>
/// A credential can have multiple status entries for different purposes (e.g., one
/// for revocation and another for suspension).
/// </para>
/// <para>
/// Common status mechanisms include:
/// </para>
/// <list type="bullet">
/// <item><description><c>BitstringStatusListEntry</c>: W3C Bitstring Status List entry.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialStatus(Id = {Id}, Type = {Type}, StatusPurpose = {StatusPurpose})")]
public class CredentialStatus: IEquatable<CredentialStatus>
{
    /// <summary>
    /// A unique identifier for this status entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The URL that identifies this specific status entry. For bitstring status lists,
    /// this typically includes the credential identifier component.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
    /// </para>
    /// </remarks>
    public string? Id { get; set; }

    /// <summary>
    /// The type of credential status mechanism.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Determines how the status should be checked and interpreted.
    /// Common values include <c>BitstringStatusListEntry</c>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#status">VC Data Model 2.0 §4.10 Status</see>.
    /// </para>
    /// </remarks>
    public required string Type { get; set; }

    /// <summary>
    /// The purpose of this status entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Indicates what kind of status this entry represents. Common values are:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>revocation</c>: Indicates whether the credential has been permanently revoked.</description></item>
    /// <item><description><c>suspension</c>: Indicates whether the credential is temporarily suspended.</description></item>
    /// </list>
    /// </remarks>
    public string? StatusPurpose { get; set; }

    /// <summary>
    /// The index within the status list for this credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used with bitstring status list mechanisms. The index identifies the bit
    /// position in the status list that corresponds to this credential.
    /// </para>
    /// </remarks>
    public string? StatusListIndex { get; set; }

    /// <summary>
    /// A reference to the status list credential containing this entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The URL of a Verifiable Credential that contains the status list.
    /// Verifiers dereference this URL to obtain the current status information.
    /// </para>
    /// </remarks>
    public string? StatusListCredential { get; set; }

    /// <summary>
    /// The size, in bits, of this status entry within the referenced status list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Absent <c>statusSize</c> is processed as <c>1</c>. When present it is an integer greater
    /// than zero, and when greater than <c>1</c>, <see cref="StatusMessage"/> is REQUIRED, with
    /// one message per possible value.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-bitstring-status-list/#statusSize">W3C Bitstring
    /// Status List 1.0 §2.1 <c>statusSize</c></see>.
    /// </para>
    /// </remarks>
    public int? StatusSize { get; set; }

    /// <summary>
    /// The status messages the issuer commits to for this entry, one per possible status value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// REQUIRED when <see cref="StatusSize"/> is greater than <c>1</c>, with a length equal to the
    /// number of possible status values <see cref="StatusSize"/> indicates. Optional when
    /// <see cref="StatusSize"/> is <c>1</c> or absent.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-bitstring-status-list/#statusMessage">W3C
    /// Bitstring Status List 1.0 §2.1 <c>statusMessage</c></see>.
    /// </para>
    /// </remarks>
    public IReadOnlyList<BitstringStatusMessage>? StatusMessage { get; set; }

    /// <summary>
    /// URL(s) dereferencing to material related to this entry's status.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An implementer MAY include this property.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-bitstring-status-list/#statusReference">W3C
    /// Bitstring Status List 1.0 §2.1 <c>statusReference</c></see>.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string>? StatusReference { get; set; }

    /// <summary>
    /// Additional properties as defined by the specific status mechanism.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Different status types may define additional properties for their operation.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <summary>
    /// Determines whether this status entry is equal to <paramref name="other"/> by comparing
    /// <see cref="Id"/>, <see cref="Type"/>, <see cref="StatusPurpose"/>, <see cref="StatusListIndex"/>,
    /// <see cref="StatusListCredential"/>, <see cref="StatusSize"/>, <see cref="StatusMessage"/> (element
    /// by element, in order) and <see cref="StatusReference"/> (element by element, in order).
    /// Equality is exact-type, not polymorphic over
    /// subtypes: a derived type adding further identity-bearing members is never equal to a
    /// same-valued instance of this type.
    /// </summary>
    /// <param name="other">The credential status to compare against.</param>
    /// <returns><see langword="true"/> if the status entries are equal; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CredentialStatus? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(GetType() != other.GetType())
        {
            return false;
        }

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Type, other.Type, StringComparison.Ordinal)
            && string.Equals(StatusPurpose, other.StatusPurpose, StringComparison.Ordinal)
            && string.Equals(StatusListIndex, other.StatusListIndex, StringComparison.Ordinal)
            && string.Equals(StatusListCredential, other.StatusListCredential, StringComparison.Ordinal)
            && StatusSize == other.StatusSize
            && AreSameMessages(StatusMessage, other.StatusMessage)
            && AreSameReferences(StatusReference, other.StatusReference);
    }


    /// <summary>
    /// Whether two <c>statusMessage</c> lists hold the same messages in the same order; two absent
    /// lists are the same, an absent and a present one are not.
    /// </summary>
    /// <param name="left">The first list, possibly absent.</param>
    /// <param name="right">The second list, possibly absent.</param>
    /// <returns><see langword="true"/> when the lists are the same; otherwise <see langword="false"/>.</returns>
    private static bool AreSameMessages(IReadOnlyList<BitstringStatusMessage>? left, IReadOnlyList<BitstringStatusMessage>? right)
    {
        if(ReferenceEquals(left, right))
        {
            return true;
        }

        return left is not null && right is not null && left.SequenceEqual(right);
    }


    /// <summary>
    /// Whether two <c>statusReference</c> lists hold the same URLs, compared ordinally, in the same
    /// order; two absent lists are the same, an absent and a present one are not.
    /// </summary>
    /// <param name="left">The first list, possibly absent.</param>
    /// <param name="right">The second list, possibly absent.</param>
    /// <returns><see langword="true"/> when the lists are the same; otherwise <see langword="false"/>.</returns>
    private static bool AreSameReferences(IReadOnlyList<string>? left, IReadOnlyList<string>? right)
    {
        if(ReferenceEquals(left, right))
        {
            return true;
        }

        return left is not null && right is not null && left.SequenceEqual(right, StringComparer.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CredentialStatus other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(Type, StringComparer.Ordinal);
        hash.Add(StatusPurpose, StringComparer.Ordinal);
        hash.Add(StatusListIndex, StringComparer.Ordinal);
        hash.Add(StatusListCredential, StringComparer.Ordinal);
        hash.Add(StatusSize);
        if(StatusMessage is not null)
        {
            foreach(BitstringStatusMessage message in StatusMessage)
            {
                hash.Add(message);
            }
        }

        if(StatusReference is not null)
        {
            foreach(string reference in StatusReference)
            {
                hash.Add(reference, StringComparer.Ordinal);
            }
        }

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(CredentialStatus? left, CredentialStatus? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(CredentialStatus? left, CredentialStatus? right) => !(left == right);
}
