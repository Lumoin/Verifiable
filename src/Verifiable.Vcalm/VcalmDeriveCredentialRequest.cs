using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §3.5.1 <c>POST /credentials/derive</c> request
/// body. The JSON-side parser (in <c>Verifiable.Json</c>) materializes this so the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps <c>System.Text.Json</c> out of the library —
/// the same parse-seam shape <see cref="VcalmIssueCredentialRequest"/> uses.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Credential"/> is the base-proofed ecdsa-sd-2023 credential to derive from — it MUST
/// already carry an embedded ecdsa-sd-2023 base proof (the holder's stored credential).
/// <see cref="SelectivePointers"/> is the §3.5.1 <c>options.selectivePointers</c> array of JSON
/// pointers naming the information to disclose; the issuer's mandatory pointers are always disclosed
/// in addition to these.
/// </para>
/// <para>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/> the credential and pointers
/// are unspecified; the endpoint maps the failure to the §2.4 / §3.5.1 HTTP outcome. A credential
/// that carries no embedded proof (not a derivable base-proofed credential) is a §3.5.1 400 the
/// endpoint detects when it inspects the parsed credential.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmDeriveCredentialRequest Failure={Failure} SelectivePointers={SelectivePointers.Length}")]
public sealed record VcalmDeriveCredentialRequest
{
    /// <summary>
    /// The base-proofed credential to derive a selectively-disclosed credential from, or
    /// <see langword="null"/> on a parse failure. Carries an embedded ecdsa-sd-2023 base proof.
    /// </summary>
    public DataIntegritySecuredCredential? Credential { get; init; }

    /// <summary>
    /// The §3.5.1 <c>options.selectivePointers</c> JSON pointers naming the selectively disclosed
    /// information. Empty when the request supplied none (the derived credential then reveals only the
    /// issuer's mandatory pointers).
    /// </summary>
    public ImmutableArray<string> SelectivePointers { get; init; } = ImmutableArray<string>.Empty;

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.5.1 → HTTP 400).</summary>
    public static VcalmDeriveCredentialRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmDeriveCredentialRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
