using System.Collections.Generic;

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
public sealed class AttachmentData
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
}
