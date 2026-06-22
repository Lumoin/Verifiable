using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm;

/// <summary>
/// The wire member NAMES of a DIDComm plaintext message — the JSON keys of the predefined message
/// headers and of the attachment and attachment-data members, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#message-headers">DIDComm Messaging v2.1 §Message Headers</see>
/// and §Attachments.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property
/// and derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>,
/// matching <see cref="Verifiable.JCose.WellKnownJoseHeaderNames"/>. The serialization converter
/// matches and writes keys against the UTF-8 spans (allocation-free); higher layers compare or
/// emit the interned strings. The <c>id</c> key is shared by a message and an attachment, so it has
/// a single constant.
/// </remarks>
public static class WellKnownDidCommMemberNames
{
    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>The <c>id</c> member — the message id, or an attachment id.</summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>The <c>type</c> message header — the Message Type URI.</summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="From"/>.</summary>
    public static ReadOnlySpan<byte> FromUtf8 => "from"u8;

    /// <summary>The <c>from</c> message header — the sender identifier.</summary>
    public static readonly string From = Utf8Constants.ToInternedString(FromUtf8);

    /// <summary>The UTF-8 source literal of <see cref="To"/>.</summary>
    public static ReadOnlySpan<byte> ToUtf8 => "to"u8;

    /// <summary>The <c>to</c> message header — the recipient identifiers.</summary>
    public static readonly string To = Utf8Constants.ToInternedString(ToUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ThreadId"/>.</summary>
    public static ReadOnlySpan<byte> ThreadIdUtf8 => "thid"u8;

    /// <summary>The <c>thid</c> message header — the thread identifier.</summary>
    public static readonly string ThreadId = Utf8Constants.ToInternedString(ThreadIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ParentThreadId"/>.</summary>
    public static ReadOnlySpan<byte> ParentThreadIdUtf8 => "pthid"u8;

    /// <summary>The <c>pthid</c> message header — the parent thread identifier.</summary>
    public static readonly string ParentThreadId = Utf8Constants.ToInternedString(ParentThreadIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CreatedTime"/>.</summary>
    public static ReadOnlySpan<byte> CreatedTimeUtf8 => "created_time"u8;

    /// <summary>The <c>created_time</c> message header — message creation time in UTC epoch seconds.</summary>
    public static readonly string CreatedTime = Utf8Constants.ToInternedString(CreatedTimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ExpiresTime"/>.</summary>
    public static ReadOnlySpan<byte> ExpiresTimeUtf8 => "expires_time"u8;

    /// <summary>The <c>expires_time</c> message header — message expiry time in UTC epoch seconds.</summary>
    public static readonly string ExpiresTime = Utf8Constants.ToInternedString(ExpiresTimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FromPrior"/>.</summary>
    public static ReadOnlySpan<byte> FromPriorUtf8 => "from_prior"u8;

    /// <summary>The <c>from_prior</c> message header — the DID Rotation JWT.</summary>
    public static readonly string FromPrior = Utf8Constants.ToInternedString(FromPriorUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PleaseAck"/>.</summary>
    public static ReadOnlySpan<byte> PleaseAckUtf8 => "please_ack"u8;

    /// <summary>The <c>please_ack</c> message header — the ids of messages whose acknowledgment is requested.</summary>
    public static readonly string PleaseAck = Utf8Constants.ToInternedString(PleaseAckUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Ack"/>.</summary>
    public static ReadOnlySpan<byte> AckUtf8 => "ack"u8;

    /// <summary>The <c>ack</c> message header — the ids of messages being acknowledged.</summary>
    public static readonly string Ack = Utf8Constants.ToInternedString(AckUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Body"/>.</summary>
    public static ReadOnlySpan<byte> BodyUtf8 => "body"u8;

    /// <summary>The <c>body</c> message header — the message-type-specific content.</summary>
    public static readonly string Body = Utf8Constants.ToInternedString(BodyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Attachments"/>.</summary>
    public static ReadOnlySpan<byte> AttachmentsUtf8 => "attachments"u8;

    /// <summary>The <c>attachments</c> message header — the attachment list.</summary>
    public static readonly string Attachments = Utf8Constants.ToInternedString(AttachmentsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Description"/>.</summary>
    public static ReadOnlySpan<byte> DescriptionUtf8 => "description"u8;

    /// <summary>The attachment <c>description</c> member.</summary>
    public static readonly string Description = Utf8Constants.ToInternedString(DescriptionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Filename"/>.</summary>
    public static ReadOnlySpan<byte> FilenameUtf8 => "filename"u8;

    /// <summary>The attachment <c>filename</c> member.</summary>
    public static readonly string Filename = Utf8Constants.ToInternedString(FilenameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MediaType"/>.</summary>
    public static ReadOnlySpan<byte> MediaTypeUtf8 => "media_type"u8;

    /// <summary>The attachment <c>media_type</c> member.</summary>
    public static readonly string MediaType = Utf8Constants.ToInternedString(MediaTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Format"/>.</summary>
    public static ReadOnlySpan<byte> FormatUtf8 => "format"u8;

    /// <summary>The attachment <c>format</c> member.</summary>
    public static readonly string Format = Utf8Constants.ToInternedString(FormatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LastModifiedTime"/>.</summary>
    public static ReadOnlySpan<byte> LastModifiedTimeUtf8 => "lastmod_time"u8;

    /// <summary>The attachment <c>lastmod_time</c> member — last-modified time in UTC epoch seconds.</summary>
    public static readonly string LastModifiedTime = Utf8Constants.ToInternedString(LastModifiedTimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ByteCount"/>.</summary>
    public static ReadOnlySpan<byte> ByteCountUtf8 => "byte_count"u8;

    /// <summary>The attachment <c>byte_count</c> member — the content size in bytes.</summary>
    public static readonly string ByteCount = Utf8Constants.ToInternedString(ByteCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Data"/>.</summary>
    public static ReadOnlySpan<byte> DataUtf8 => "data"u8;

    /// <summary>The attachment <c>data</c> member.</summary>
    public static readonly string Data = Utf8Constants.ToInternedString(DataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jws"/>.</summary>
    public static ReadOnlySpan<byte> JwsUtf8 => "jws"u8;

    /// <summary>The attachment data <c>jws</c> member — a detached-content JWS over the attachment.</summary>
    public static readonly string Jws = Utf8Constants.ToInternedString(JwsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Hash"/>.</summary>
    public static ReadOnlySpan<byte> HashUtf8 => "hash"u8;

    /// <summary>The attachment data <c>hash</c> member — a multihash integrity check.</summary>
    public static readonly string Hash = Utf8Constants.ToInternedString(HashUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Links"/>.</summary>
    public static ReadOnlySpan<byte> LinksUtf8 => "links"u8;

    /// <summary>The attachment data <c>links</c> member — by-reference content locations.</summary>
    public static readonly string Links = Utf8Constants.ToInternedString(LinksUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Base64"/>.</summary>
    public static ReadOnlySpan<byte> Base64Utf8 => "base64"u8;

    /// <summary>The attachment data <c>base64</c> member — base64url inline content.</summary>
    public static readonly string Base64 = Utf8Constants.ToInternedString(Base64Utf8);

    /// <summary>The UTF-8 source literal of <see cref="Json"/>.</summary>
    public static ReadOnlySpan<byte> JsonUtf8 => "json"u8;

    /// <summary>The attachment data <c>json</c> member — embedded inline JSON content.</summary>
    public static readonly string Json = Utf8Constants.ToInternedString(JsonUtf8);
}
