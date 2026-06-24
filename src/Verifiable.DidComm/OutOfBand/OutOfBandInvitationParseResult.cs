namespace Verifiable.DidComm.OutOfBand;

/// <summary>
/// The reason parsing an Out-of-Band invitation URL failed, or <see cref="None"/> when it succeeded.
/// Decoding an OOB URL is fail-closed — the URL is untrusted input, so every malformed or
/// non-conformant outcome is reported as one of these typed reasons rather than thrown to the caller
/// (DIDComm v2.1 §Out Of Band Messages).
/// </summary>
public enum OutOfBandUrlParseError
{
    /// <summary>The URL parsed into a conformant Out-of-Band invitation.</summary>
    None = 0,

    /// <summary>The URL carries no <c>_oob</c> query parameter (DIDComm v2.1 §Standard Message Encoding: the parameter is required).</summary>
    OobUrlMissingParameter,

    /// <summary>The <c>_oob</c> value is not decodable base64url, or its bytes are not a structurally valid plaintext JWM.</summary>
    OobValueMalformed,

    /// <summary>The decoded message's <c>type</c> is not the invitation Message Type URI (DIDComm v2.1 §Invitation).</summary>
    OobNotAnInvitation,

    /// <summary>The decoded invitation has no <c>from</c> header (DIDComm v2.1 §Invitation: from is REQUIRED for OOB usage).</summary>
    OobMissingFrom,

    /// <summary>The decoded invitation has no <c>id</c> header (DIDComm v2.1 §Invitation: id is REQUIRED and becomes the response pthid).</summary>
    OobMissingId,

    /// <summary>The <c>_oob</c> value exceeds the hard length bound and is rejected before decoding, so an attacker-controlled value cannot drive an unbounded allocation (DIDComm v2.1 §Privacy Considerations: the URL is observed, unauthenticated input).</summary>
    OobValueTooLong,

    /// <summary>The URL is ambiguous — <c>_oob</c> appears more than once, or alongside the shortened-form <c>_oobid</c> — and is rejected rather than silently taking the first occurrence (DIDComm v2.1 §Standard Message Encoding reserves <c>_oob</c>).</summary>
    OobUrlAmbiguousParameter
}


/// <summary>
/// The outcome of parsing a DIDComm Out-of-Band invitation URL — the recovered invitation
/// <see cref="DidCommMessage"/> when <see cref="IsSuccessful"/> is <see langword="true"/>, or an
/// <see cref="Error"/> reason otherwise.
/// </summary>
/// <remarks>
/// Produced by <see cref="OutOfBandInvitationExtensions.TryParseOutOfBandUrl"/>, which never throws to
/// the caller: the <c>_oob</c> value is observed, unauthenticated wire input (DIDComm v2.1 §Privacy
/// Considerations), so a missing parameter, a malformed encoding, or a non-conformant invitation each
/// becomes a typed <see cref="OutOfBandUrlParseError"/> rather than an exception.
/// </remarks>
public sealed record OutOfBandInvitationParseResult
{
    private OutOfBandInvitationParseResult(bool isSuccessful, DidCommMessage? invitation, OutOfBandUrlParseError error)
    {
        IsSuccessful = isSuccessful;
        Invitation = invitation;
        Error = error;
    }


    /// <summary>Whether the URL parsed into a conformant Out-of-Band invitation.</summary>
    public bool IsSuccessful { get; }

    /// <summary>The recovered invitation when <see cref="IsSuccessful"/> is <see langword="true"/>, otherwise <see langword="null"/>.</summary>
    public DidCommMessage? Invitation { get; }

    /// <summary>The reason parsing failed, or <see cref="OutOfBandUrlParseError.None"/> when it succeeded.</summary>
    public OutOfBandUrlParseError Error { get; }


    //Mints a successful result carrying the recovered invitation.
    internal static OutOfBandInvitationParseResult Success(DidCommMessage invitation)
    {
        return new OutOfBandInvitationParseResult(true, invitation, OutOfBandUrlParseError.None);
    }


    //Mints a failed result carrying the typed rejection reason.
    internal static OutOfBandInvitationParseResult Failed(OutOfBandUrlParseError error)
    {
        return new OutOfBandInvitationParseResult(false, invitation: null, error);
    }
}
