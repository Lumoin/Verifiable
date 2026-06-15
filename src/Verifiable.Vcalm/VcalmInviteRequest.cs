using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.7.5 inviteRequest body — the
/// <c>{url, purpose, referenceId?}</c> a local system POSTs to the
/// <c>/{localInviteId}/invite-request/response</c> endpoint to signal where to send an individual for
/// a use-case-specific interaction. The JSON-side parser materializes it so the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// <para>
/// §3.7.5: "this specification does not state any requirements as to how the 'url' field is formatted,
/// but does recommend that an implementer of this interaction mechanism make use of a unique ID"
/// (carried as <see cref="ReferenceId"/>, a <c>urn:uuid:</c>-shaped value in the §3.7.5 examples). The
/// <see cref="Url"/> and <see cref="Purpose"/> are the two members the §3.7.5 examples always carry;
/// <see cref="ReferenceId"/> is OPTIONAL.
/// </para>
/// <para>
/// §2.4 strictness: a body that is not a JSON object, omits the <see cref="Url"/>, or carries a
/// top-level member the endpoint does not recognize yields <see cref="VcalmParseFailure.Malformed"/> /
/// <see cref="VcalmParseFailure.UnknownOption"/> rather than being silently accepted.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmInviteRequest Failure={Failure}")]
public sealed record VcalmInviteRequest
{
    /// <summary>
    /// The §3.7.5 <c>url</c> — the URL the remote system should send the individual to (e.g. a website
    /// where a person can engage in a use-case-specific interaction). Format is the implementer's
    /// choice (§3.7.5 states no requirement on it).
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.7.5 states no requirement on how the url field is formatted; it is carried verbatim, so System.Uri would reject formats the spec explicitly permits and lose the wire shape.")]
    public string? Url { get; init; }

    /// <summary>
    /// The §3.7.5 <c>purpose</c> — a human-readable description of the interaction the <see cref="Url"/>
    /// leads to (e.g. "Checkout at ShopCo"), or <see langword="null"/> when the request omits it.
    /// </summary>
    public string? Purpose { get; init; }

    /// <summary>
    /// The §3.7.5 OPTIONAL <c>referenceId</c> — the recommended unique id correlating the invitation
    /// (a <c>urn:uuid:</c> value in the §3.7.5 examples), or <see langword="null"/> when omitted.
    /// </summary>
    public string? ReferenceId { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.7.5 → HTTP 400).</summary>
    public static VcalmInviteRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-member parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmInviteRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
