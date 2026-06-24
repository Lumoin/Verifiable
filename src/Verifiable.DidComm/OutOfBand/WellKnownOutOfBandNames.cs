using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.OutOfBand;

/// <summary>
/// The well-known names of the DIDComm Out-of-Band invitation: the invitation Message Type URI, the
/// URL query parameter keys reserved by the §Standard Message Encoding / §Short URL Message Retrieval
/// forms, and the body field keys of the invitation, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#out-of-band-messages">DIDComm Messaging v2.1 §Out Of Band Messages</see>.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and
/// derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="WellKnownDidCommMemberNames"/>. The three groups are kept distinct: the invitation MTURI
/// is the message <c>type</c> header value; the <c>_oob</c> / <c>_oobid</c> keys are URL query
/// parameter names (never JSON members); and goal_code / goal / accept are members of the invitation
/// <c>body</c> object.
/// </remarks>
public static class WellKnownOutOfBandNames
{
    /// <summary>The UTF-8 source literal of <see cref="InvitationType"/>.</summary>
    public static ReadOnlySpan<byte> InvitationTypeUtf8 => "https://didcomm.org/out-of-band/2.0/invitation"u8;

    /// <summary>
    /// The invitation Message Type URI — the value of the <c>type</c> header that identifies a message
    /// as an Out-of-Band invitation (DIDComm v2.1 §Invitation: "type … REQUIRED").
    /// </summary>
    public static readonly string InvitationType = Utf8Constants.ToInternedString(InvitationTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OobQueryKey"/>.</summary>
    public static ReadOnlySpan<byte> OobQueryKeyUtf8 => "_oob"u8;

    /// <summary>
    /// The reserved URL query parameter name carrying the base64url-encoded plaintext JWM
    /// (DIDComm v2.1 §Standard Message Encoding: "The <c>_oob</c> query parameter is required and is
    /// reserved to contain the DIDComm message string.").
    /// </summary>
    public static readonly string OobQueryKey = Utf8Constants.ToInternedString(OobQueryKeyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OobIdQueryKey"/>.</summary>
    public static ReadOnlySpan<byte> OobIdQueryKeyUtf8 => "_oobid"u8;

    /// <summary>
    /// The reserved URL query parameter name of the shortened form, carrying the GUID the agent
    /// resolves to the full message via an HTTP GET (DIDComm v2.1 §Short URL Message Retrieval: "Note
    /// the replacement of the query parameter <c>_oob</c> with <c>_oobid</c> when using shortened URL.").
    /// </summary>
    public static readonly string OobIdQueryKey = Utf8Constants.ToInternedString(OobIdQueryKeyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GoalCode"/>.</summary>
    public static ReadOnlySpan<byte> GoalCodeUtf8 => "goal_code"u8;

    /// <summary>
    /// The invitation body <c>goal_code</c> member — OPTIONAL self-attested code the receiver may
    /// display or use to decide what to do with the invitation (DIDComm v2.1 §Invitation).
    /// </summary>
    public static readonly string GoalCode = Utf8Constants.ToInternedString(GoalCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Goal"/>.</summary>
    public static ReadOnlySpan<byte> GoalUtf8 => "goal"u8;

    /// <summary>
    /// The invitation body <c>goal</c> member — OPTIONAL self-attested string describing the
    /// context-specific goal of the invitation (DIDComm v2.1 §Invitation).
    /// </summary>
    public static readonly string Goal = Utf8Constants.ToInternedString(GoalUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Accept"/>.</summary>
    public static ReadOnlySpan<byte> AcceptUtf8 => "accept"u8;

    /// <summary>
    /// The invitation body <c>accept</c> member — an OPTIONAL array of media types, in preference
    /// order, identifying the DIDComm Messaging profiles the endpoint supports (DIDComm v2.1
    /// §Invitation).
    /// </summary>
    public static readonly string Accept = Utf8Constants.ToInternedString(AcceptUtf8);
}
