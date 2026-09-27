using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// A §3.4.2 "Query By Example" query entry: a <see cref="CredentialQuery"/> describing the claims a
/// verifier needs from one or more verifiable credentials, optionally constrained to particular
/// accepted issuers, cryptosuites, and envelope formats.
/// </summary>
/// <remarks>
/// The §3.4.2 selective-disclosure note governs the example: "Any field included in a Query By
/// Example is a required field." A field whose value is the empty string requests the field with no
/// expectation of any value (the §3.4.2 "leave the value as an empty string" rule); a field with a
/// non-empty value additionally constrains the disclosed value.
/// </remarks>
[DebuggerDisplay("QueryByExample Group={Group}")]
public sealed record QueryByExampleQuery: VcalmPresentationQuery
{
    /// <summary>The §3.4.2 <c>credentialQuery</c> single object carrying the example and acceptance constraints.</summary>
    public required QueryByExampleCredentialQuery CredentialQuery { get; init; }
}


/// <summary>
/// The §3.4.2 <c>credentialQuery</c> object: the example credential plus the verifier's acceptance
/// constraints.
/// </summary>
[DebuggerDisplay("QueryByExampleCredentialQuery Reason={Reason}")]
public sealed record QueryByExampleCredentialQuery
{
    /// <summary>The §3.4.2 OPTIONAL <c>reason</c> — a human-readable explanation the holder's software MAY display.</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// The §3.4.2 OPTIONAL <c>example</c> object indicating which credential and claims are needed.
    /// <see langword="null"/> when the query carries only acceptance constraints.
    /// </summary>
    public QueryByExampleCredential? Example { get; init; }

    /// <summary>
    /// The §3.4.2 OPTIONAL <c>acceptedIssuers</c> — the issuers the verifier recognizes. Empty when
    /// the query places no issuer constraint (any issuer is acceptable).
    /// </summary>
    public ImmutableArray<QueryByExampleAcceptedIssuer> AcceptedIssuers { get; init; } =
        ImmutableArray<QueryByExampleAcceptedIssuer>.Empty;

    /// <summary>
    /// The §3.4.2 OPTIONAL <c>acceptedCryptosuites</c> — the proof suites the verifier will accept
    /// (e.g. <c>ecdsa-sd-2023</c>, <c>bbs-2023</c> to signal selective-disclosure acceptance). Empty
    /// when unconstrained.
    /// </summary>
    public ImmutableArray<string> AcceptedCryptosuites { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>
    /// The §3.4.2 OPTIONAL <c>acceptedEnvelopes</c> — the envelope media types the verifier will
    /// accept (e.g. <c>application/jwt</c>). Empty when unconstrained.
    /// </summary>
    public ImmutableArray<string> AcceptedEnvelopes { get; init; } = ImmutableArray<string>.Empty;
}


/// <summary>
/// The §3.4.2 <c>example</c> object: the credential <c>@context</c>, <c>type</c>, and the requested
/// <c>credentialSubject</c> fields.
/// </summary>
/// <remarks>
/// Every field carried here is a §3.4.2 REQUIRED-if-present field. <see cref="SubjectFields"/> maps a
/// requested subject claim name to its requested value; a value of <see cref="string.Empty"/> means
/// "this field is requested, any value satisfies it".
/// </remarks>
[DebuggerDisplay("QueryByExampleCredential Types={Types.Length} SubjectFields={SubjectFields.Count}")]
public sealed record QueryByExampleCredential
{
    /// <summary>The §3.4.2 <c>example.@context</c> values. Empty when the example omits <c>@context</c>.</summary>
    public ImmutableArray<string> Context { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>
    /// The §3.4.2 <c>example.type</c> values — the credential type(s) the example requests. The wire
    /// allows a single string or an array; both normalize to this list. Empty when the example omits
    /// <c>type</c>.
    /// </summary>
    public ImmutableArray<string> Types { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>
    /// The §3.4.2 <c>example.credentialSubject</c> requested fields: a claim name → requested value
    /// map where an empty-string value means "any value satisfies the field". Empty when the example
    /// requests no subject fields (a type-only match).
    /// </summary>
    public ImmutableDictionary<string, string> SubjectFields { get; init; } =
        ImmutableDictionary<string, string>.Empty;
}


/// <summary>
/// A single §3.4.2 <c>acceptedIssuers</c> item. The §3.4.2 wire allows three shapes: a bare URL
/// string, an object with an <c>id</c>, or an object with a <c>recognizedIn</c> reference to a
/// <c>RecognizedEntityCredential</c> (<see cref="VcalmParameterNames.RecognizedEntityCredential"/>).
/// The neutral model carries whichever was present.
/// </summary>
/// <remarks>
/// A <c>recognizedIn</c> item names a list, not an issuer: "the list contains recognized issuers that
/// are acceptable to the verifier"
/// (<see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>). The issuers on
/// that list are known only once the caller has retrieved and verified the referenced credential, so
/// the caller supplies them in <see cref="RecognizedIssuerIds"/>; until it does, the item accepts no
/// issuer.
/// </remarks>
[DebuggerDisplay("AcceptedIssuer Id={Id} RecognizedInId={RecognizedInId} RecognizedIssuerIds={RecognizedIssuerIds.Length}")]
public sealed record QueryByExampleAcceptedIssuer
{
    /// <summary>
    /// The direct issuer identifier — the §3.4.2 bare-URL string item or the object's <c>id</c>
    /// member. <see langword="null"/> when the item used the <c>recognizedIn</c> form instead.
    /// </summary>
    public string? Id { get; init; }

    /// <summary>
    /// The §3.4.2 <c>recognizedIn.id</c> — the URL of a <c>RecognizedEntityCredential</c>
    /// listing the issuers the verifier accepts. <see langword="null"/> when the item used the direct
    /// <c>id</c> / URL form instead.
    /// </summary>
    /// <remarks>
    /// The request's author chose this URL, and any valid URL string passes the parser, whatever its
    /// scheme or host. A caller that retrieves the list does so only through its own outbound-fetch
    /// policy (the schemes and hosts it allows), never by dereferencing this value directly.
    /// </remarks>
    public string? RecognizedInId { get; init; }

    /// <summary>
    /// The issuer identifiers the caller took from the retrieved and verified
    /// <c>RecognizedEntityCredential</c> that <see cref="RecognizedInId"/> points to. Empty by default:
    /// the request parser never sets it, because the request carries only the list's URL, not its
    /// verified content. A <c>recognizedIn</c> item matches a credential only when the credential's
    /// issuer id is among these identifiers, compared exactly; with none supplied (an empty or a
    /// <see langword="default"/> array) it matches no issuer. Ignored on a direct <see cref="Id"/> item.
    /// </summary>
    public ImmutableArray<string> RecognizedIssuerIds { get; init; } = ImmutableArray<string>.Empty;
}
