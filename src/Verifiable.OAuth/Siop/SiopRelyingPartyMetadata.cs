using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// The Relying Party metadata a non-pre-registered RP passes to a Self-Issued OP in the
/// <c>client_metadata</c> Authorization Request parameter (or serves at the
/// <c>client_metadata_uri</c>), per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-7.5">SIOPv2 §7.5</see>.
/// </summary>
/// <remarks>
/// The Self-Issued OP returns an Authorization Response only when it supports all
/// received RP parameter values; otherwise it errors with one of the
/// <see cref="SiopErrors"/> codes (§10). Other OpenID Connect Dynamic Client
/// Registration parameters MAY accompany these; <see cref="AdditionalParameters"/>
/// carries them opaquely (e.g. <c>redirect_uris</c>, <c>jwks_uri</c>,
/// <c>id_token_encrypted_response_alg</c>).
/// </remarks>
[DebuggerDisplay("SiopRelyingPartyMetadata SubjectSyntaxTypes={SubjectSyntaxTypesSupported.Count}")]
public sealed record SiopRelyingPartyMetadata
{
    /// <summary>
    /// §7.5 <c>subject_syntax_types_supported</c> (REQUIRED): the Subject Syntax Type
    /// identifiers the RP supports — <see cref="SiopSubjectSyntaxTypes.JwkThumbprint"/>
    /// and/or <c>did:</c>-prefixed method identifiers (bare <c>did</c> for all methods).
    /// </summary>
    public required IReadOnlyList<string> SubjectSyntaxTypesSupported { get; init; }

    /// <summary>
    /// The <c>id_token_signed_response_alg</c> registration parameter — the JWS
    /// algorithm the RP expects the Self-Issued ID Token to be signed with — or
    /// <see langword="null"/> to omit it.
    /// </summary>
    public string? IdTokenSignedResponseAlg { get; init; }

    /// <summary>
    /// Additional OpenID Connect Dynamic Client Registration parameters, emitted
    /// verbatim through <see cref="JsonAppender.AppendValue"/> (strings, numbers,
    /// booleans, string lists, and nested dictionaries), or <see langword="null"/>.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalParameters { get; init; }
}
