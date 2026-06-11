using System.Diagnostics;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// The outcome of a Self-Issued OP (wallet) validating the Relying Party's inbound
/// Authorization Request per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-7.4">SIOPv2 §7.4</see>
/// and
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-10.3">SIOPv2 §10.3</see>.
/// Produced by <see cref="SiopRequestValidation.Validate"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the mirror of <see cref="SelfIssuedIdTokenValidationResult"/>: that type
/// records the RP validating the OP's <c>id_token</c> response, this one records the OP
/// validating the RP's request. Each independent §7.4 / §10.3 check surfaces as its own
/// predicate flag so the OP can distinguish failure modes; <see cref="IsValid"/> is the
/// conjunction, and <see cref="ErrorCode"/> carries the single
/// <see cref="SiopErrors"/> code to return when a check fails.
/// </para>
/// <para>
/// §10.3: "A Self-Issued OpenID Provider Response is returned when Self-Issued OP
/// supports all Relying Party parameter values received from the Relying Party in the
/// <c>client_metadata</c> parameter. If one or more of the Relying Party parameter
/// Values is not supported, Self-Issued OP MUST return an error according to Section
/// 10.3." The flags below decompose that conjunction so the precise failing value is
/// observable.
/// </para>
/// </remarks>
[DebuggerDisplay("SiopRequestValidationResult IsValid={IsValid} ErrorCode={ErrorCode}")]
public sealed record SiopRequestValidationResult
{
    /// <summary>
    /// Whether the RP-metadata source is consistent per §7.4 and §9: a pre-registered
    /// Client ID does not also carry <c>client_metadata</c>/<c>client_metadata_uri</c>,
    /// and <c>client_metadata</c> and <c>client_metadata_uri</c> are not both present.
    /// </summary>
    public bool IsMetadataSourceConsistent { get; init; }

    /// <summary>
    /// Whether at least one Subject Syntax Type the RP communicated in
    /// <c>subject_syntax_types_supported</c> is one the OP supports (§10.3
    /// <c>subject_syntax_types_not_supported</c>).
    /// </summary>
    public bool IsSubjectSyntaxSupported { get; init; }

    /// <summary>
    /// Whether every Relying Party <c>client_metadata</c> parameter value the request
    /// carries is one the OP honors — the <c>id_token_signed_response_alg</c> and any
    /// further governed values (§10.3 <c>client_metadata_value_not_supported</c>).
    /// </summary>
    public bool AreClientMetadataValuesSupported { get; init; }

    /// <summary>
    /// Whether dereferencing <c>client_metadata_uri</c> succeeded, when the request used
    /// that source. <see langword="true"/> when the request carried no
    /// <c>client_metadata_uri</c>, since there was nothing to dereference (§10.3
    /// <c>invalid_client_metadata_uri</c>).
    /// </summary>
    public bool IsClientMetadataUriResolved { get; init; }

    /// <summary>
    /// The <see cref="SiopErrors"/> code the OP returns to the RP, or
    /// <see langword="null"/> when the request is valid. Carries the single most-specific
    /// spec-mandated error when more than one check fails (see
    /// <see cref="SiopRequestValidation"/> for the precedence).
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Whether every §7.4 / §10.3 check passed: a consistent metadata source, at least
    /// one OP-supported Subject Syntax Type, only OP-supported <c>client_metadata</c>
    /// values, and a resolved <c>client_metadata_uri</c> when that source was used.
    /// </summary>
    public bool IsValid =>
        IsMetadataSourceConsistent
        && IsSubjectSyntaxSupported
        && AreClientMetadataValuesSupported
        && IsClientMetadataUriResolved;
}
