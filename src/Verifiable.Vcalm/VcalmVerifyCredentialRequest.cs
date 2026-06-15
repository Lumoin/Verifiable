using System.Diagnostics;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §3.3.1 <c>POST /credentials/verify</c> request
/// body. The JSON-side parser (in <c>Verifiable.Json</c>) materializes this so the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps <c>System.Text.Json</c> out of the library
/// — the same parse-seam shape every request body the library reads crosses.
/// </summary>
/// <remarks>
/// <para>
/// Exactly one of <see cref="DataIntegrityCredential"/> or <see cref="EnvelopedCredential"/> is
/// populated, discriminating the §3.3.1 "one of the following schemas" alternatives: an embedded
/// Data Integrity credential, or an <c>EnvelopedVerifiableCredential</c> (the <c>data:</c>-URL
/// secured form). <see cref="CredentialJson"/> is the verbatim JSON of the credential member,
/// preserved so the endpoint can echo it under <c>credential</c> when <c>options.returnCredential</c>
/// is set "in the form in which it was verified" without re-serializing.
/// </para>
/// <para>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/>, the credential members
/// and options are unspecified; the endpoint maps the failure to the §2.4 / §3.3.1 HTTP outcome.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmVerifyCredentialRequest Failure={Failure}")]
public sealed record VcalmVerifyCredentialRequest
{
    /// <summary>
    /// The parsed embedded-secured credential, or <see langword="null"/> when the request carried an
    /// enveloped credential instead.
    /// </summary>
    public DataIntegritySecuredCredential? DataIntegrityCredential { get; init; }

    /// <summary>
    /// The parsed <c>EnvelopedVerifiableCredential</c>, or <see langword="null"/> when the request
    /// carried an embedded Data Integrity credential instead.
    /// </summary>
    public EnvelopedVerifiableCredential? EnvelopedCredential { get; init; }

    /// <summary>
    /// The verbatim JSON of the <c>verifiableCredential</c> member, for the §3.3.1
    /// <c>options.returnCredential</c> echo. <see langword="null"/> on a parse failure.
    /// </summary>
    public string? CredentialJson { get; init; }

    /// <summary>The parsed verify options (§2.4 all-optional). Defaulted when absent.</summary>
    public VcalmVerifyOptions Options { get; init; } = new();

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§3.3.1 → HTTP 400).</summary>
    public static VcalmVerifyCredentialRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmVerifyCredentialRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}
