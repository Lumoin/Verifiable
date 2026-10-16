using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Claims the first use of a DPoP proof's <paramref name="jti"/> at <paramref name="targetUri"/> in one atomic operation:
/// when the store holds no live record of the pair (<paramref name="targetUri"/>, <paramref name="jti"/>), it records the
/// pair until <paramref name="recordUntil"/> and answers <see cref="JtiReplayOutcome.FirstUse"/>; when it holds one, it
/// answers <see cref="JtiReplayOutcome.Replayed"/> and records nothing. Two concurrent consultations of one pair answer
/// <see cref="JtiReplayOutcome.FirstUse"/> at most once.
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of the
/// target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof
/// JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI for which the jti
/// value has been seen before would be declined.")
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> calls it once per validated proof, after the proof's
/// <c>jti</c> has passed the rule a record can hold (not empty, at most <see cref="JtiReplayGuard.MaxJtiLength"/> UTF-16
/// code units, no character of general category Cc and no unpaired surrogate), with
/// <see cref="ProtectedResource.DpopResourceRequest.TargetUri"/> in the normalized form below, and a
/// <paramref name="recordUntil"/> one tick past the proof's acceptance window, so a store reading the instant either as the
/// last one the record counts or as the first one it does not count refuses a replay at the window's last instant.
/// </para>
/// <para>
/// The normalized form is the one the library compares a proof's <c>htu</c> in and keys every <c>jti</c> record by
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "servers SHOULD employ
/// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of [RFC3986])
/// before comparing the htu claim."): the scheme and host in lower case, a default port dropped, dot segments removed, an
/// empty path given <c>/</c>, no userinfo, query or fragment, only the percent-encodings of unreserved characters
/// decoded and the hexadecimal digits of every other percent-encoding in upper case
/// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2">RFC 3986 Sections 6.2.2</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.3">6.2.3</see>), the host kept as written. A space, a
/// control character, an octet outside US-ASCII and every reserved character in the path stay percent-encoded.
/// <see cref="Uri.OriginalString"/> of <paramref name="targetUri"/> carries exactly that text, and the text normalized
/// again is itself, so a store keying by it keys one target by one string whatever the application's spelling, and one
/// <c>jti</c> at two target URIs is two records.
/// </para>
/// <para>
/// The answers: <see cref="JtiReplayOutcome.FirstUse"/> continues the decision; <see cref="JtiReplayOutcome.Replayed"/>
/// is refused <c>invalid_dpop_proof</c> with the description "The DPoP proof jti has been presented previously.";
/// <see cref="JtiReplayOutcome.Unacceptable"/>, a <c>jti</c> the store cannot hold by a rule of its own, is refused
/// <c>invalid_dpop_proof</c> as a malformed proof with the description "DPoP proof jti is empty, too long or carries a
/// character the replay guard cannot store."; <see cref="JtiReplayOutcome.StoreUnavailable"/>, a store that cannot
/// record or cannot resolve what it recorded, fails closed as 500 <c>server_error</c> with the description "The DPoP
/// proof jti store could not record the proof." and no challenge; any other value fails closed as 500
/// <c>server_error</c> too. A store never answers <see cref="JtiReplayOutcome.FirstUse"/> without having recorded the
/// pair.
/// </para>
/// </remarks>
/// <param name="jti">The proof's <c>jti</c>.</param>
/// <param name="targetUri">The target URI the proof was presented at, in its normalized form, the record's context.</param>
/// <param name="recordUntil">The instant the record is kept until.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The outcome of the claim.</returns>
public delegate ValueTask<JtiReplayOutcome> ConsultDpopProofJtiDelegate(
    string jti,
    Uri targetUri,
    DateTimeOffset recordUntil,
    ExchangeContext context,
    CancellationToken cancellationToken);
