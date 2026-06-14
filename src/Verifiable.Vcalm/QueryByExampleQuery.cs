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
/// <c>VerifiableRecognitionCredential</c>. The neutral model carries whichever was present.
/// </summary>
[DebuggerDisplay("AcceptedIssuer Id={Id} RecognizedInId={RecognizedInId}")]
public sealed record QueryByExampleAcceptedIssuer
{
    /// <summary>
    /// The direct issuer identifier — the §3.4.2 bare-URL string item or the object's <c>id</c>
    /// member. <see langword="null"/> when the item used the <c>recognizedIn</c> form instead.
    /// </summary>
    public string? Id { get; init; }

    /// <summary>
    /// The §3.4.2 <c>recognizedIn.id</c> — the URL of a <c>VerifiableRecognitionCredential</c>
    /// listing the issuers the verifier accepts. <see langword="null"/> when the item used the direct
    /// <c>id</c> / URL form instead.
    /// </summary>
    public string? RecognizedInId { get; init; }
}
