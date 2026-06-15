using System.Diagnostics;
using Verifiable.Core.StatusList;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §C.3 <c>POST /credentials/status</c> request
/// body. The JSON-side parser (in <c>Verifiable.Json</c>) materializes this so the
/// <c>Verifiable.Vcalm</c> serialization firewall keeps <c>System.Text.Json</c> out of the library —
/// the same parse-seam shape <see cref="VcalmIssueCredentialRequest"/> uses.
/// </summary>
/// <remarks>
/// <para>
/// §C.3 body: <c>{credentialId, credentialStatus{id, type, statusPurpose, statusListIndex,
/// statusListCredential}, status (boolean), indexAllocator?}</c>. The <see cref="Entry"/> reuses the
/// Core <see cref="BitstringStatusListEntry"/> — the same typed view a credential carries — so the
/// update seam loads the named status list, sets / clears the bit at
/// <see cref="BitstringStatusListEntry.StatusListIndex"/>, and re-secures the list.
/// </para>
/// <para>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/> the members are
/// unspecified; the endpoint maps the failure to the §C.3 / §2.4 HTTP outcome.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmUpdateStatusRequest CredentialId={CredentialId} Status={Status} Failure={Failure}")]
public sealed record VcalmUpdateStatusRequest
{
    /// <summary>
    /// §C.3 <c>credentialId</c>: "Identifies the credential (the identifier does not have to appear
    /// in the VC itself)." The §C.3 404 key when the status service holds no record for it.
    /// </summary>
    public string? CredentialId { get; init; }

    /// <summary>
    /// The parsed §C.3 <c>credentialStatus</c> entry naming the status list and the bit to update,
    /// or <see langword="null"/> on a parse failure.
    /// </summary>
    public BitstringStatusListEntry? Entry { get; init; }

    /// <summary>
    /// §C.3 <c>status</c>: the new boolean status — <see langword="true"/> sets the bit (revoke /
    /// suspend), <see langword="false"/> clears it.
    /// </summary>
    public bool Status { get; init; }

    /// <summary>
    /// §C.3 <c>indexAllocator</c>: "For services to use which indexes are being used/assigned to
    /// VCs." Opaque to the library; threaded verbatim to the update seam. <see langword="null"/> when absent.
    /// </summary>
    public string? IndexAllocator { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§C.3 → HTTP 400).</summary>
    public static VcalmUpdateStatusRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmUpdateStatusRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}


/// <summary>
/// The neutral, parser-produced view of a VCALM 1.0 §C.1 <c>POST /status-lists</c> request body:
/// <c>{statusPurpose, id?, options?}</c>. §C.1 is a MAY supporting interface (the §1.3 binding
/// status-service MUST is §C.3).
/// </summary>
/// <remarks>
/// When <see cref="Failure"/> is not <see cref="VcalmParseFailure.None"/> the members are
/// unspecified; the endpoint maps the failure to the §C.1 / §2.4 HTTP outcome.
/// </remarks>
[DebuggerDisplay("VcalmCreateStatusListRequest StatusPurpose={StatusPurpose} Id={Id} Failure={Failure}")]
public sealed record VcalmCreateStatusListRequest
{
    /// <summary>
    /// §C.1 <c>statusPurpose</c>: "The purpose of the status list (e.g., 'revocation',
    /// 'suspension'). This determines what type of status information the list will track."
    /// </summary>
    public string? StatusPurpose { get; init; }

    /// <summary>
    /// §C.1 <c>id</c>: "Optional identifier for the status list. If not provided, the service will
    /// generate one." <see langword="null"/> when absent.
    /// </summary>
    public string? Id { get; init; }

    /// <summary>The strict-parse outcome; <see cref="VcalmParseFailure.None"/> on success.</summary>
    public VcalmParseFailure Failure { get; init; }


    /// <summary>Creates a malformed-body parse failure (§C.1 → HTTP 400).</summary>
    public static VcalmCreateStatusListRequest Malformed() =>
        new() { Failure = VcalmParseFailure.Malformed };


    /// <summary>Creates an unknown-option parse failure (§2.4 → HTTP 400 / UNKNOWN_OPTION_PROVIDED).</summary>
    public static VcalmCreateStatusListRequest UnknownOption() =>
        new() { Failure = VcalmParseFailure.UnknownOption };
}


/// <summary>
/// The outcome of a VCALM 1.0 §C.3 status update the application's update seam reports, which the
/// endpoint maps to the §C.3 HTTP response (200 / 404).
/// </summary>
/// <remarks>
/// §C.3 responses: 200 "Credential status successfully updated", 400 "Bad Request" (the library
/// answers malformed / unknown-option requests before the seam runs), 404 "Credential not found".
/// This enum carries the seam's success / not-found verdict; it mirrors the
/// <see cref="CredentialStatusUpdateOutcome"/> shape the Core batch seam returns.
/// </remarks>
public enum VcalmStatusUpdateOutcome
{
    /// <summary>§C.3 200: the bit was set / cleared and the status-list credential re-secured.</summary>
    Updated,

    /// <summary>
    /// §C.3 404: the status service holds no record for the named credential or status list. "404
    /// Credential not found."
    /// </summary>
    NotFound
}
