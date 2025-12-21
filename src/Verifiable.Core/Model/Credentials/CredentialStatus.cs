using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

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
/// <item><description><c>BitstringStatusListEntry</c>: Efficient bitstring-based status lists.</description></item>
/// <item><description><c>RevocationList2020Status</c>: Legacy revocation list format.</description></item>
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
    /// Additional properties as defined by the specific status mechanism.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Different status types may define additional properties for their operation.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
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

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Type, other.Type, StringComparison.Ordinal)
            && string.Equals(StatusPurpose, other.StatusPurpose, StringComparison.Ordinal)
            && string.Equals(StatusListIndex, other.StatusListIndex, StringComparison.Ordinal)
            && string.Equals(StatusListCredential, other.StatusListCredential, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is CredentialStatus other && Equals(other);


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