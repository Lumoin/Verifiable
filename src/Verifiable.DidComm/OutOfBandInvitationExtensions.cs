using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;

namespace Verifiable.DidComm;

/// <summary>
/// Build, encode, and parse for DIDComm Out-of-Band invitations — the single message a sender presents
/// as a URL or QR code to bootstrap an interaction, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#out-of-band-messages">DIDComm Messaging v2.1 §Out Of Band Messages</see>.
/// </summary>
/// <remarks>
/// <para>
/// An invitation is an ordinary <see cref="DidCommMessage"/> whose <c>type</c> is the invitation
/// Message Type URI, carrying goal_code / goal / accept in its <c>body</c> and optional alternative
/// protocol messages as attachments — there is no parallel typed model. The §Standard Message Encoding
/// form is a URL with a base64url-encoded plaintext JWM in the reserved <c>_oob</c> query parameter;
/// the §Short URL Message Retrieval form replaces it with <c>_oobid</c> carrying a GUID the receiver
/// resolves with an HTTP GET. This project performs NO fetch: that GET is the application's transport
/// concern (DIDComm v2.1 §Short URL Message Retrieval).
/// </para>
/// <para>
/// All serialization runs through the injected <see cref="DidCommMessageSerializer"/> /
/// <see cref="DidCommMessageParser"/> and the base64url <see cref="EncodeDelegate"/> /
/// <see cref="DecodeDelegate"/> over a caller-supplied <see cref="MemoryPool{T}"/>, keeping this
/// transport-agnostic project free of <see cref="System.Text.Json"/> and of <c>System.Net</c>. The URL
/// the base64url value lands in is built with the separator trick rather than round-tripped through
/// <see cref="System.Uri"/>, because base64url is URL-safe and needs no escaping, and the verbatim
/// string is what the QR encoder consumes and the length validator measures.
/// </para>
/// </remarks>
public static class OutOfBandInvitationExtensions
{
    //The invitation Message Type URI, parsed once for semver-compatible handler dispatch.
    private static readonly MessageTypeUri InvitationMessageType = MessageTypeUri.Parse(WellKnownOutOfBandNames.InvitationType);


    /// <summary>
    /// The advisory QR-code length bound: past this many characters a deployment MAY prefer the
    /// shortened <c>_oobid</c> form for broader scanner interoperability (DIDComm v2.1 §Short URL
    /// Message Retrieval).
    /// </summary>
    public const int QrAdvisoryLength = 400;

    /// <summary>
    /// The hard QR-code length bound — the maximum a single Version-40 QR code carries in alphanumeric
    /// mode (ISO 18004). Past this a URL cannot be a single QR code, so the sender MUST switch to the
    /// shortened form (DIDComm v2.1 §Short URL Message Retrieval).
    /// </summary>
    public const int QrMaximumLength = 4296;

    /// <summary>
    /// The hard upper bound on the length of the untrusted <c>_oob</c> value accepted on the decode path
    /// before it is handed to the base64url decoder. The §Standard Message Encoding form permits a long
    /// URL for non-QR delivery (email, deep link), so this is well above the QR bounds; it caps the decode
    /// allocation an attacker-controlled value can drive, since the URL is observed, unauthenticated input
    /// (DIDComm v2.1 §Privacy Considerations).
    /// </summary>
    public const int MaximumOobValueLength = 1024 * 1024;


    /// <summary>
    /// Builds an Out-of-Band invitation as a <see cref="DidCommMessage"/> whose <c>type</c> is the
    /// invitation Message Type URI, populating the <c>body</c> goal_code / goal / accept members that
    /// are supplied and attaching <paramref name="attachments"/> (the alternative protocol messages a
    /// receiver may choose one of).
    /// </summary>
    /// <param name="from">REQUIRED. The sender's DID, conveyed for the receiver's future interactions (DIDComm v2.1 §Invitation: from is REQUIRED for OOB usage).</param>
    /// <param name="id">REQUIRED. The invitation id, which the receiver MUST use as the response <c>pthid</c> (DIDComm v2.1 §Message Correlation).</param>
    /// <param name="goalCode">OPTIONAL. A self-attested code the receiver may display or use to decide what to do.</param>
    /// <param name="goal">OPTIONAL. A self-attested string describing the context-specific goal.</param>
    /// <param name="accept">OPTIONAL. The media-type profiles the endpoint supports, in preference order.</param>
    /// <param name="attachments">OPTIONAL. Alternative protocol messages, in preference order; the receiver acts on only one.</param>
    /// <returns>The invitation message.</returns>
    public static DidCommMessage CreateOutOfBandInvitation(
        string from,
        string id,
        string? goalCode = null,
        string? goal = null,
        IReadOnlyList<string>? accept = null,
        IList<Attachment>? attachments = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(from);
        ArgumentException.ThrowIfNullOrEmpty(id);

        var body = new Dictionary<string, object>();

        if(goalCode is not null)
        {
            body[WellKnownOutOfBandNames.GoalCode] = goalCode;
        }

        if(goal is not null)
        {
            body[WellKnownOutOfBandNames.Goal] = goal;
        }

        if(accept is not null)
        {
            //The accept array is carried as a list of strings; the serializer emits a JSON array and the
            //parser recovers it as a List<object> of strings (the accessor below reads either shape).
            body[WellKnownOutOfBandNames.Accept] = new List<object>(accept);
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownOutOfBandNames.InvitationType,
            From = from,
            Body = body,
            Attachments = attachments
        };
    }


    /// <summary>
    /// Whether <paramref name="message"/> is an Out-of-Band invitation — its <c>type</c> names the
    /// invitation Message Type URI (DIDComm v2.1 §Invitation). The comparison is the spec-mandated MTURI
    /// dispatch match (<see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/>): protocol and message
    /// names ignoring case and punctuation, same major version, under the same documentation URI.
    /// </summary>
    /// <param name="message">The message to test.</param>
    /// <returns><see langword="true"/> when the message is an invitation.</returns>
    public static bool IsOutOfBandInvitation(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(InvitationMessageType);
    }


    /// <summary>Reads the invitation body <c>goal_code</c> member, or <see langword="null"/> when absent.</summary>
    /// <param name="invitation">The invitation message.</param>
    /// <returns>The goal code, or <see langword="null"/>.</returns>
    public static string? GetOutOfBandGoalCode(this DidCommMessage invitation)
    {
        ArgumentNullException.ThrowIfNull(invitation);

        return ReadBodyString(invitation, WellKnownOutOfBandNames.GoalCode);
    }


    /// <summary>Reads the invitation body <c>goal</c> member, or <see langword="null"/> when absent.</summary>
    /// <param name="invitation">The invitation message.</param>
    /// <returns>The goal, or <see langword="null"/>.</returns>
    public static string? GetOutOfBandGoal(this DidCommMessage invitation)
    {
        ArgumentNullException.ThrowIfNull(invitation);

        return ReadBodyString(invitation, WellKnownOutOfBandNames.Goal);
    }


    /// <summary>
    /// Reads the invitation body <c>accept</c> media-type profiles, in preference order, or an empty
    /// list when absent.
    /// </summary>
    /// <param name="invitation">The invitation message.</param>
    /// <returns>The accept profiles, or an empty list.</returns>
    public static IReadOnlyList<string> GetOutOfBandAccept(this DidCommMessage invitation)
    {
        ArgumentNullException.ThrowIfNull(invitation);

        if(invitation.Body is null || !invitation.Body.TryGetValue(WellKnownOutOfBandNames.Accept, out object? value))
        {
            return [];
        }

        //The accept member is a JSON array; the parser recovers it as a List<object> of strings, while a
        //freshly built invitation carries the same shape. Either way each entry is projected to a string.
        return value switch
        {
            IEnumerable<object> items => [.. ProjectStrings(items)],
            _ => []
        };
    }


    /// <summary>
    /// Sets <paramref name="response"/>'s <c>pthid</c> to <paramref name="invitation"/>'s <c>id</c>,
    /// correlating a response with the invitation that triggered it (DIDComm v2.1 §Message Correlation:
    /// "The id of the message passed in a URL or a QR code is used as the pthid on a response sent by
    /// the recipient of this message.").
    /// </summary>
    /// <param name="response">The response message whose parent thread id is set.</param>
    /// <param name="invitation">The invitation whose id becomes the response's parent thread id.</param>
    public static void CorrelateToOutOfBandInvitation(this DidCommMessage response, DidCommMessage invitation)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(invitation);

        if(string.IsNullOrEmpty(invitation.Id))
        {
            throw new ArgumentException(
                "The invitation MUST carry an 'id' to correlate a response (DIDComm v2.1 §Message Correlation).",
                nameof(invitation));
        }

        response.ParentThreadId = invitation.Id;
    }


    /// <summary>
    /// Encodes <paramref name="invitation"/> as a §Standard Message Encoding URL —
    /// <c>&lt;baseUrl&gt;?_oob=&lt;base64url(plaintext JWM)&gt;</c> — resolving the base64url codec from
    /// the <see cref="DefaultCoderSelector"/> registry (the JWK key format the registry keys base64url
    /// under). Delegates to the explicit-codec overload after selecting the <see cref="EncodeDelegate"/>.
    /// </summary>
    /// <param name="invitation">The invitation message. Its <c>type</c> MUST be the invitation MTURI, with <c>from</c> and <c>id</c> present.</param>
    /// <param name="baseUrl">The <c>&lt;domain&gt;/&lt;path&gt;</c> the <c>_oob</c> parameter is appended to.</param>
    /// <param name="serializer">The serializer producing the plaintext JWM bytes.</param>
    /// <param name="memoryPool">The pool the pack buffer is drawn from.</param>
    /// <returns>The §Standard Message Encoding URL.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The base URL is the verbatim <domain>/<path> string the deployment supplies; round-tripping it through System.Uri would normalize it and would offer nothing over the separator-trick append of the URL-safe base64url _oob value.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "The OOB URL is the verbatim wire string the QR encoder consumes and the length validator measures; the base64url _oob value is URL-safe so it needs no escaping, and System.Uri would re-encode it and normalize away the base URL the deployment supplied.")]
    public static string ToOutOfBandUrl(
        this DidCommMessage invitation,
        string baseUrl,
        DidCommMessageSerializer serializer,
        MemoryPool<byte> memoryPool)
    {
        EncodeDelegate base64UrlEncoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        return invitation.ToOutOfBandUrl(baseUrl, serializer, base64UrlEncoder, memoryPool);
    }


    /// <summary>
    /// Encodes <paramref name="invitation"/> as a §Standard Message Encoding URL using an explicit
    /// base64url <paramref name="base64UrlEncoder"/>. The registry-resolving overload delegates here.
    /// </summary>
    /// <param name="invitation">The invitation message. Its <c>type</c> MUST be the invitation MTURI, with <c>from</c> and <c>id</c> present.</param>
    /// <param name="baseUrl">The <c>&lt;domain&gt;/&lt;path&gt;</c> the <c>_oob</c> parameter is appended to.</param>
    /// <param name="serializer">The serializer producing the plaintext JWM bytes.</param>
    /// <param name="base64UrlEncoder">The base64url encoder for the plaintext JWM bytes.</param>
    /// <param name="memoryPool">The pool the pack buffer is drawn from.</param>
    /// <returns>The §Standard Message Encoding URL.</returns>
    /// <exception cref="ArgumentException">Thrown when the message is not a conformant invitation — a producer-side guard.</exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The base URL is the verbatim <domain>/<path> string the deployment supplies; round-tripping it through System.Uri would normalize it and would offer nothing over the separator-trick append of the URL-safe base64url _oob value.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "The OOB URL is the verbatim wire string the QR encoder consumes and the length validator measures; the base64url _oob value is URL-safe so it needs no escaping, and System.Uri would re-encode it and normalize away the base URL the deployment supplied.")]
    public static string ToOutOfBandUrl(
        this DidCommMessage invitation,
        string baseUrl,
        DidCommMessageSerializer serializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentException.ThrowIfNullOrEmpty(baseUrl);
        ArgumentNullException.ThrowIfNull(serializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Producer-side OOB MUSTs: only a conformant invitation may be encoded into a URL. These mirror
        //the from_prior mint guard — the sender does not emit a message every conformant receiver would
        //reject (DIDComm v2.1 §Invitation: type / from / id are REQUIRED).
        if(!invitation.IsOutOfBandInvitation())
        {
            throw new ArgumentException(
                "Only an Out-of-Band invitation (type == the invitation Message Type URI) may be encoded into an OOB URL (DIDComm v2.1 §Invitation).",
                nameof(invitation));
        }

        if(string.IsNullOrEmpty(invitation.From))
        {
            throw new ArgumentException(
                "An Out-of-Band invitation MUST carry a 'from' header (DIDComm v2.1 §Invitation).",
                nameof(invitation));
        }

        if(string.IsNullOrEmpty(invitation.Id))
        {
            throw new ArgumentException(
                "An Out-of-Band invitation MUST carry an 'id' header (DIDComm v2.1 §Invitation).",
                nameof(invitation));
        }

        //PackPlaintext re-runs the §Message Headers structural validation and serializes whitespace-free
        //(the serializer emits compact JSON), satisfying the §Standard Message Encoding "whitespace from
        //the json string should be eliminated" guidance.
        using DidCommPlaintextMessage packed = invitation.PackPlaintext(serializer, memoryPool);
        string encoded = base64UrlEncoder(packed.AsReadOnlySpan());

        //The _oob value is URL-safe base64url, appended verbatim; '&' when the base URL already carries a
        //query, else '?' (mirrors VcalmInteractionUrlComposer).
        char separator = baseUrl.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        return baseUrl + separator + WellKnownOutOfBandNames.OobQueryKey + '=' + encoded;
    }


    /// <summary>
    /// Parses an Out-of-Band invitation URL of the §Standard Message Encoding form, resolving the
    /// base64url decoder from the <see cref="DefaultCoderSelector"/> registry. Delegates to the
    /// explicit-codec overload after selecting the <see cref="DecodeDelegate"/>.
    /// </summary>
    /// <param name="url">The §Standard Message Encoding URL carrying the <c>_oob</c> parameter.</param>
    /// <param name="parser">The parser producing the message from the plaintext JWM bytes.</param>
    /// <param name="memoryPool">The pool the decode buffer is drawn from.</param>
    /// <param name="result">The recovered invitation, or the typed failure reason.</param>
    /// <returns><see langword="true"/> when a conformant invitation was recovered.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The URL is the verbatim wire string scanned from a QR code or pasted by a user; the _oob value is read by ordinal key match, never by re-parsing the URL through System.Uri (which would re-encode the base64url value).")]
    public static bool TryParseOutOfBandUrl(
        string url,
        DidCommMessageParser parser,
        MemoryPool<byte> memoryPool,
        out OutOfBandInvitationParseResult result)
    {
        DecodeDelegate base64UrlDecoder = DefaultCoderSelector.SelectDecoder(WellKnownKeyFormats.PublicKeyJwk);

        return TryParseOutOfBandUrl(url, parser, base64UrlDecoder, memoryPool, out result);
    }


    /// <summary>
    /// Parses an Out-of-Band invitation URL of the §Standard Message Encoding form using an explicit
    /// base64url <paramref name="base64UrlDecoder"/>, recovering the invitation from its <c>_oob</c>
    /// query parameter. The registry-resolving overload delegates here. Fail-closed: the URL is
    /// untrusted, observed input (DIDComm v2.1 §Privacy Considerations), so every malformed or
    /// non-conformant outcome is returned as a typed <see cref="OutOfBandUrlParseError"/> and never
    /// thrown to the caller.
    /// </summary>
    /// <param name="url">The §Standard Message Encoding URL carrying the <c>_oob</c> parameter.</param>
    /// <param name="parser">The parser producing the message from the plaintext JWM bytes.</param>
    /// <param name="base64UrlDecoder">The base64url decoder for the <c>_oob</c> value.</param>
    /// <param name="memoryPool">The pool the decode buffer is drawn from.</param>
    /// <param name="result">The recovered invitation, or the typed failure reason.</param>
    /// <returns><see langword="true"/> when a conformant invitation was recovered.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The URL is the verbatim wire string scanned from a QR code or pasted by a user; the _oob value is read by ordinal key match, never by re-parsing the URL through System.Uri (which would re-encode the base64url value).")]
    public static bool TryParseOutOfBandUrl(
        string url,
        DidCommMessageParser parser,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        out OutOfBandInvitationParseResult result)
    {
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(string.IsNullOrEmpty(url) || !TryGetQueryValue(url, WellKnownOutOfBandNames.OobQueryKey, out string? oobValue))
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobUrlMissingParameter);

            return false;
        }

        //The _oob value is observed, unauthenticated input; bound its length first so a hostile value
        //cannot drive an unbounded pool allocation (an OutOfMemoryException would be outside the
        //fail-closed catch below). The bound is well above any QR-deliverable invitation.
        if(oobValue.Length > MaximumOobValueLength)
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobValueTooLong);

            return false;
        }

        //An ambiguous OOB URL — _oob present more than once, or carried alongside the shortened-form
        //_oobid — is not well-formed; a different layer (a logger, the application's _oobid fetcher) could
        //key on the other occurrence, so reject it fail-closed rather than silently taking the first. The
        //_oobid arm key-COUNTS (like the _oob arm) rather than requiring a value, so a bare or empty
        //`_oobid` (which a fetcher could still act on) is caught, not just a valued one.
        if(CountQueryKey(url, WellKnownOutOfBandNames.OobQueryKey) > 1
            || CountQueryKey(url, WellKnownOutOfBandNames.OobIdQueryKey) > 0)
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobUrlAmbiguousParameter);

            return false;
        }

        //The _oob value is untrusted wire input: a non-base64url value, malformed JWM bytes, or a message
        //that fails the §Message Headers structural validation are all reported as a typed malformed
        //failure (the leaf decoder throws FormatException, the parser throws FormatException/JsonException,
        //and UnpackPlaintext's ValidateStructure throws FormatException). None escapes to the caller.
        DidCommMessage message;
        try
        {
            using IMemoryOwner<byte> decoded = base64UrlDecoder(oobValue, memoryPool);
            message = DidCommPlaintextExtensions.UnpackPlaintext(decoded.Memory.Span, parser);
        }
        catch(Exception ex) when(ex is FormatException or System.Text.Json.JsonException or ArgumentException)
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobValueMalformed);

            return false;
        }

        //Consumer-side OOB MUSTs: the decoded message MUST be an invitation with from and id present
        //(DIDComm v2.1 §Invitation). UnpackPlaintext already guaranteed a non-empty id of a valid-MTURI
        //type, but the invitation-specific type and the OOB-required from are checked here.
        if(!message.IsOutOfBandInvitation())
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobNotAnInvitation);

            return false;
        }

        if(string.IsNullOrEmpty(message.From))
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobMissingFrom);

            return false;
        }

        //Defense-in-depth: UnpackPlaintext's §Message Headers validation already rejects an empty id (it
        //surfaces as OobValueMalformed above), so this guard is unreachable in the current pipeline; it
        //keeps the from/id symmetry and fails closed if that upstream check ever stops covering id.
        if(string.IsNullOrEmpty(message.Id))
        {
            result = OutOfBandInvitationParseResult.Failed(OutOfBandUrlParseError.OobMissingId);

            return false;
        }

        result = OutOfBandInvitationParseResult.Success(message);

        return true;
    }


    /// <summary>
    /// Composes the §Short URL Message Retrieval form — <c>&lt;baseUrl&gt;?_oobid=&lt;oobId&gt;</c> —
    /// the sender presents instead of the full <c>_oob</c> URL when the full message is too long for a
    /// usable QR code. The receiver does an HTTP GET against this URL to retrieve the full message; that
    /// GET is the application's transport concern, not this library's (DIDComm v2.1 §Short URL Message
    /// Retrieval).
    /// </summary>
    /// <param name="baseUrl">The <c>&lt;domain&gt;/&lt;path&gt;</c> the <c>_oobid</c> parameter is appended to.</param>
    /// <param name="oobId">The GUID the sender tracks for the full message.</param>
    /// <returns>The §Short URL Message Retrieval URL.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The base URL is the verbatim <domain>/<path> string the deployment supplies; the separator-trick append of the opaque _oobid GUID offers nothing to gain from round-tripping through System.Uri.")]
    [SuppressMessage("Design", "CA1055:URI-like return values should not be strings",
        Justification = "The shortened URL is the verbatim wire string the QR encoder consumes; System.Uri would re-encode the appended _oobid value and normalize away the base URL the deployment supplied.")]
    public static string ToShortenedOutOfBandUrl(string baseUrl, string oobId)
    {
        ArgumentException.ThrowIfNullOrEmpty(baseUrl);
        ArgumentException.ThrowIfNullOrEmpty(oobId);

        char separator = baseUrl.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        return baseUrl + separator + WellKnownOutOfBandNames.OobIdQueryKey + '=' + oobId;
    }


    /// <summary>
    /// Extracts the <c>_oobid</c> GUID from a §Short URL Message Retrieval URL. Fail-closed: a URL
    /// without an <c>_oobid</c> parameter yields <see langword="false"/> with a <see langword="null"/>
    /// id and never throws.
    /// </summary>
    /// <param name="url">The §Short URL Message Retrieval URL.</param>
    /// <param name="id">The extracted <c>_oobid</c> value, or <see langword="null"/> when absent.</param>
    /// <returns><see langword="true"/> when an <c>_oobid</c> value was extracted.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The URL is the verbatim wire string scanned or pasted; the _oobid value is read by ordinal key match, not by re-parsing the URL through System.Uri.")]
    public static bool TryGetShortenedOutOfBandId(string url, [NotNullWhen(true)] out string? id)
    {
        if(!string.IsNullOrEmpty(url) && TryGetQueryValue(url, WellKnownOutOfBandNames.OobIdQueryKey, out string? value))
        {
            id = value;

            return true;
        }

        id = null;

        return false;
    }


    /// <summary>
    /// Validates an Out-of-Band invitation URL against the QR-code length bounds. The library does NOT
    /// render the QR image (ISO 18004 encoding is the application's presentation concern); it validates
    /// the URL the QR would carry. A URL over <see cref="QrMaximumLength"/> cannot be a single QR code
    /// (not valid); a URL over <see cref="QrAdvisoryLength"/> is valid with the advisory flag set so the
    /// deployment can switch to the shortened form (DIDComm v2.1 §Short URL Message Retrieval).
    /// </summary>
    /// <param name="url">The Out-of-Band invitation URL to validate.</param>
    /// <returns>The validation outcome carrying the URL length, the hard-bound result, and the advisory flag.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "The URL is the verbatim wire string being length-checked; System.Uri would not change the character count the QR bounds constrain.")]
    public static OutOfBandUrlValidation ValidateOutOfBandQrBounds(string url)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);

        int length = url.Length;
        bool isWithinHardBound = length <= QrMaximumLength;
        bool isWithinAdvisoryBound = length <= QrAdvisoryLength;

        return new OutOfBandUrlValidation
        {
            UrlLength = length,
            IsValid = isWithinHardBound,
            HasAdvisory = isWithinHardBound && !isWithinAdvisoryBound
        };
    }


    //Reads a string-valued member of the invitation body, or null when the body or member is absent or
    //is not a string.
    private static string? ReadBodyString(DidCommMessage invitation, string memberName)
    {
        if(invitation.Body is not null && invitation.Body.TryGetValue(memberName, out object? value) && value is string text)
        {
            return text;
        }

        return null;
    }


    //Projects each element of an object sequence to its string value, skipping non-string elements.
    private static IEnumerable<string> ProjectStrings(IEnumerable<object> items)
    {
        foreach(object item in items)
        {
            if(item is string text)
            {
                yield return text;
            }
        }
    }


    //Extracts the verbatim value of an ordinal-matched query key from a URL string. The OOB query values
    //(_oob = URL-safe base64url, _oobid = a GUID) carry no characters that require percent-decoding, so
    //the value is returned as-is — no System.Uri round-trip (which would re-decode the base64url value).
    //A key with no '=' or an empty value is treated as absent.
    private static bool TryGetQueryValue(string url, string key, [NotNullWhen(true)] out string? value)
    {
        int queryStart = url.IndexOf('?', StringComparison.Ordinal);
        if(queryStart < 0)
        {
            value = null;

            return false;
        }

        ReadOnlySpan<char> query = ClipFragment(url.AsSpan(queryStart + 1));

        foreach(Range pairRange in query.Split('&'))
        {
            ReadOnlySpan<char> pair = query[pairRange];
            int equals = pair.IndexOf('=');
            if(equals < 0)
            {
                continue;
            }

            if(pair[..equals].SequenceEqual(key) && equals + 1 < pair.Length)
            {
                value = new string(pair[(equals + 1)..]);

                return true;
            }
        }

        value = null;

        return false;
    }


    //Counts how many query pairs carry the given ordinal key (regardless of value); used to reject an
    //ambiguous URL that repeats a reserved OOB parameter.
    private static int CountQueryKey(string url, string key)
    {
        int queryStart = url.IndexOf('?', StringComparison.Ordinal);
        if(queryStart < 0)
        {
            return 0;
        }

        ReadOnlySpan<char> query = ClipFragment(url.AsSpan(queryStart + 1));

        int count = 0;
        foreach(Range pairRange in query.Split('&'))
        {
            ReadOnlySpan<char> pair = query[pairRange];
            int equals = pair.IndexOf('=');
            ReadOnlySpan<char> pairKey = equals < 0 ? pair : pair[..equals];
            if(pairKey.SequenceEqual(key))
            {
                count++;
            }
        }

        return count;
    }


    //Clips a trailing URL fragment, which is not part of the query, so a '#fragment' cannot fold into the
    //last parameter's value.
    private static ReadOnlySpan<char> ClipFragment(ReadOnlySpan<char> query)
    {
        int fragmentStart = query.IndexOf('#');

        return fragmentStart >= 0 ? query[..fragmentStart] : query;
    }
}
