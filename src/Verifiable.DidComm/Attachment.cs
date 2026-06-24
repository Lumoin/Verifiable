using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.DidComm;

/// <summary>
/// A DIDComm message attachment — arbitrary supplemental content attached to a message in much the
/// way attachments work in email, as defined in
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#attachments">DIDComm Messaging v2.1 §Attachments</see>.
/// </summary>
/// <remarks>
/// Attachments are carried in the <see cref="DidCommMessage.Attachments"/> list. Only
/// <see cref="Data"/> is required; every other member is an optional hint.
/// </remarks>
public sealed class Attachment: IEquatable<Attachment>
{
    /// <summary>
    /// An identifier for the attachment, unique within the message, so it can be referenced (for
    /// example by an attachment URI). When present it MUST consist entirely of unreserved URI
    /// characters so it needs no percent-encoding.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>A human-readable description of the content.</summary>
    public string? Description { get; set; }

    /// <summary>A hint at the filename to use if the attachment is persisted as a file.</summary>
    public string? Filename { get; set; }

    /// <summary>The media type of the attached content.</summary>
    public string? MediaType { get; set; }

    /// <summary>A further description of the attachment's format when <see cref="MediaType"/> is not sufficient.</summary>
    public string? Format { get; set; }

    /// <summary>A hint at when the attached content was last modified, in UTC epoch seconds.</summary>
    public long? LastModifiedTime { get; set; }

    /// <summary>
    /// A hint at the size of the content in bytes — mostly relevant when the content is included by
    /// reference — so the receiver can estimate the cost of fetching it.
    /// </summary>
    public long? ByteCount { get; set; }

    /// <summary>The object giving access to the actual content. Required.</summary>
    public AttachmentData? Data { get; set; }


    /// <summary>
    /// Determines whether this attachment equals <paramref name="other"/> by value over its hint members and its
    /// <see cref="Data"/> (compared via <see cref="AttachmentData"/> value equality).
    /// </summary>
    /// <param name="other">The attachment to compare with, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the two attachments are value-equal.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Attachment? other)
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
            && string.Equals(Description, other.Description, StringComparison.Ordinal)
            && string.Equals(Filename, other.Filename, StringComparison.Ordinal)
            && string.Equals(MediaType, other.MediaType, StringComparison.Ordinal)
            && string.Equals(Format, other.Format, StringComparison.Ordinal)
            && LastModifiedTime == other.LastModifiedTime
            && ByteCount == other.ByteCount
            && Equals(Data, other.Data);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is Attachment other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(Description, StringComparer.Ordinal);
        hash.Add(Filename, StringComparer.Ordinal);
        hash.Add(MediaType, StringComparer.Ordinal);
        hash.Add(Format, StringComparer.Ordinal);
        hash.Add(LastModifiedTime);
        hash.Add(ByteCount);
        hash.Add(Data);

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two <see cref="Attachment"/> instances are value-equal.</summary>
    public static bool operator ==(Attachment? left, Attachment? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="Attachment"/> instances differ.</summary>
    public static bool operator !=(Attachment? left, Attachment? right) => !(left == right);
}
