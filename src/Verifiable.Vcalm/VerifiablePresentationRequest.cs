using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral model of a W3C VCALM 1.0 §3.4.1 verifiable presentation request (VPR) — the request a
/// verifier makes to a holder for a presentation
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>). A VPR is a payload a verifier sends to a holder, carried inside a §3.6 exchange
/// or §3.7 interaction; this type is the parsed, transport- and serializer-neutral view the holder
/// reasons over.
/// </summary>
/// <remarks>
/// <para>
/// The §3.4.1 body is <c>{ query[], domain?, challenge? }</c>. <see cref="Query"/> is the REQUIRED
/// extension point — one or more typed <see cref="VcalmPresentationQuery"/> entries, each of which
/// MUST define a string <c>type</c>. <see cref="Domain"/> binds the presentation to a specific
/// verifier (an anti-replay target the holder MUST check against its communication channel per
/// §3.4.3.2), and <see cref="Challenge"/> is the anti-replay nonce the holder echoes in the
/// presentation proof.
/// </para>
/// <para>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/> the remaining members are
/// unspecified; the parse failure is the strict-parse outcome (§3.4.1: each query MUST define a
/// type — a query entry without one yields <see cref="VcalmParseFailure.Malformed"/>).
/// </para>
/// </remarks>
[DebuggerDisplay("VerifiablePresentationRequest Queries={Query.Length} Failure={Failure}")]
public sealed record VerifiablePresentationRequest
{
    /// <summary>
    /// The §3.4.1 REQUIRED <c>query</c> array: one or more typed query entries. The array carries the
    /// §3.4.5 grouping that <see cref="VprEvaluator"/> resolves into AND / OR satisfaction.
    /// </summary>
    public ImmutableArray<VcalmPresentationQuery> Query { get; init; } = ImmutableArray<VcalmPresentationQuery>.Empty;

    /// <summary>
    /// The §3.4.1 OPTIONAL <c>domain</c> — the target security domain the holder binds the
    /// presentation to and checks against the current channel, protecting the verifier against
    /// replay attacks. <see langword="null"/> when the request omits it.
    /// </summary>
    public string? Domain { get; init; }

    /// <summary>
    /// The §3.4.1 OPTIONAL <c>challenge</c> — the random nonce the holder includes in the
    /// presentation proof, protecting the verifier against replay attacks. <see langword="null"/>
    /// when the request omits it.
    /// </summary>
    public string? Challenge { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.4.1 → the carrying exchange maps to HTTP 400).</summary>
    public static VerifiablePresentationRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → the carrying exchange maps to HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VerifiablePresentationRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
