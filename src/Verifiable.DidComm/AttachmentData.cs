using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Foundation;

namespace Verifiable.DidComm;

/// <summary>
/// The <c>data</c> object of a DIDComm attachment, giving access to the attached content, as
/// defined in
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#attachments">DIDComm Messaging v2.1 §Attachments</see>.
/// </summary>
/// <remarks>
/// A conforming <c>data</c> object MUST contain at least one of the subfields below, and enough of
/// them to allow access to the content. When the content is referenced via <see cref="Links"/>,
/// <see cref="Hash"/> MUST be present as an integrity check.
/// </remarks>
public sealed class AttachmentData: IEquatable<AttachmentData>
{
    /// <summary>
    /// A JWS in detached content mode signing the attachment. The signature need not come from the
    /// author of the message. Held as arbitrary JSON (a JWS JSON serialization object).
    /// </summary>
    public object? Jws { get; set; }

    /// <summary>
    /// The hash of the content in multihash format. Used as an integrity check, and REQUIRED when
    /// the content is referenced via <see cref="Links"/>.
    /// </summary>
    public string? Hash { get; set; }

    /// <summary>Zero or more locations at which the content may be fetched (attachment by reference).</summary>
    public IList<string>? Links { get; set; }

    /// <summary>Base64url-encoded inline content (attachment by value).</summary>
    public string? Base64 { get; set; }

    /// <summary>
    /// Directly embedded JSON content, when the content is natively conveyable as JSON. Held as
    /// arbitrary JSON.
    /// </summary>
    public object? Json { get; set; }


    /// <summary>
    /// Determines whether this attachment data equals <paramref name="other"/> by value: <see cref="Hash"/> and
    /// <see cref="Base64"/> by ordinal comparison, <see cref="Links"/> element-wise in order, and the arbitrary-JSON
    /// <see cref="Jws"/> and <see cref="Json"/> by deep structural comparison (<see cref="StructuralEquality.JsonEqual"/>).
    /// </summary>
    /// <param name="other">The attachment data to compare with, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the two are value-equal.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(AttachmentData? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Hash, other.Hash, StringComparison.Ordinal)
            && string.Equals(Base64, other.Base64, StringComparison.Ordinal)
            && StructuralEquality.SequenceEqual(Links, other.Links)
            && StructuralEquality.JsonEqual(Jws, other.Jws)
            && StructuralEquality.JsonEqual(Json, other.Json);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is AttachmentData other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Hash, StringComparer.Ordinal);
        hash.Add(Base64, StringComparer.Ordinal);
        hash.Add(StructuralEquality.SequenceHashCode(Links));
        hash.Add(StructuralEquality.JsonHashCode(Jws));
        hash.Add(StructuralEquality.JsonHashCode(Json));

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two <see cref="AttachmentData"/> instances are value-equal.</summary>
    public static bool operator ==(AttachmentData? left, AttachmentData? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="AttachmentData"/> instances differ.</summary>
    public static bool operator !=(AttachmentData? left, AttachmentData? right) => !(left == right);
}
