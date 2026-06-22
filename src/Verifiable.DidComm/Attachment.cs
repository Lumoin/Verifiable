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
public sealed class Attachment
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
}
