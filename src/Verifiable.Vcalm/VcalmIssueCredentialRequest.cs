using System.Diagnostics;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §3.2.1 <c>POST /credentials/issue</c> request
/// body. The JSON-side parser (in <c>Verifiable.Json</c>) materializes this so the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps <c>System.Text.Json</c> out of the library —
/// the same parse-seam shape <see cref="VcalmVerifyCredentialRequest"/> uses.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Credential"/> is the unsecured (or caller-pre-proofed) VC-DM 2.0 credential to secure.
/// <see cref="HasExistingProof"/> records whether the caller supplied <c>credential.proof</c>, so the
/// endpoint can apply the §3.2.1 existing-proof configuration without re-inspecting the wire JSON.
/// <see cref="CredentialId"/> is the <c>credential.id</c> the parser read (the §3.2.1 auto-populate
/// source); <see cref="Options"/> carries the parsed <c>options</c>.
/// </para>
/// <para>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/> the credential members and
/// options are unspecified; the endpoint maps the failure to the §2.4 / §3.2.1 HTTP outcome.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmIssueCredentialRequest Failure={Failure}")]
public sealed record VcalmIssueCredentialRequest
{
    /// <summary>The parsed credential to secure, or <see langword="null"/> on a parse failure.</summary>
    public VerifiableCredential? Credential { get; init; }

    /// <summary>
    /// The <c>credential.id</c> the request carried, or <see langword="null"/> when the credential
    /// has no <c>id</c>. The §3.2.1 auto-populate source for <c>credentialId</c>.
    /// </summary>
    public string? CredentialId { get; init; }

    /// <summary>
    /// Whether the supplied credential already carried a <c>proof</c> member (§3.2.1 existing-proof
    /// case: handled per the instance's <see cref="VcalmExistingProofHandling"/> configuration).
    /// </summary>
    public bool HasExistingProof { get; init; }

    /// <summary>The parsed issue options (§2.4 all-optional). Defaulted when absent.</summary>
    public VcalmIssueOptions Options { get; init; } = new();

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.2.1 → HTTP 400).</summary>
    public static VcalmIssueCredentialRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmIssueCredentialRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
