using Verifiable.Core;
using Verifiable.Core.StatusList;

namespace Verifiable.Vcalm;

/// <summary>
/// Parses a VCALM 1.0 §C.3 <c>POST /credentials/status</c> request body into the neutral
/// <see cref="VcalmUpdateStatusRequest"/>. The default <c>System.Text.Json</c> implementation lives
/// in <c>Verifiable.Json</c> and is wired by the application — same serialization-firewall and
/// strict-parse contract as <see cref="ParseVcalmIssueCredentialDelegate"/>.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object, omits the REQUIRED <c>credentialStatus</c> /
/// <c>status</c>, or carries an unrecognized top-level member is returned as the corresponding
/// <see cref="VcalmParseFailure"/> rather than thrown — the endpoint maps the failure to the §C.3 /
/// §2.4 HTTP outcome.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmUpdateStatusRequest?> ParseVcalmUpdateStatusDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a VCALM 1.0 §C.1 <c>POST /status-lists</c> request body into the neutral
/// <see cref="VcalmCreateStatusListRequest"/>. The default implementation lives in
/// <c>Verifiable.Json</c>; same strict-parse contract as <see cref="ParseVcalmUpdateStatusDelegate"/>.
/// </summary>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmCreateStatusListRequest?> ParseVcalmCreateStatusListDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Applies a VCALM 1.0 §C.3 status update behind the application's storage boundary: load the
/// status-list credential named by <paramref name="entry"/>'s <c>statusListCredential</c>, set or
/// clear the bit at its <c>statusListIndex</c> per <paramref name="status"/>, re-encode and re-secure
/// the list, and persist it. The library owns no storage; it composes the §C.3 boundary checks and
/// dispatches to this seam, then maps the returned <see cref="VcalmStatusUpdateOutcome"/> to the §C.3
/// HTTP response.
/// </summary>
/// <remarks>
/// <para>
/// This is the VCALM-endpoint counterpart of the Core
/// <see cref="UpdateCredentialStatusesDelegate"/> batch seam: that one is batch-shaped and
/// transport-only (no per-request context), whereas the §C.3 endpoint updates exactly one entry per
/// call and threads the verify/update request's <see cref="ExchangeContext"/> for tenant scoping and
/// the SSRF policy. An application MAY back this seam with the Core batch delegate by wrapping the
/// single change in a one-element <see cref="CredentialStatusChange"/> list (Core
/// <see cref="StatusList.Set(int, byte)"/> flips the bit, <see cref="BitstringStatusListCodec.EncodeList"/>
/// re-encodes it).
/// </para>
/// <para>
/// Returning <see cref="VcalmStatusUpdateOutcome.NotFound"/> for an unknown credential or an unknown
/// status list yields the §C.3 404; <see cref="VcalmStatusUpdateOutcome.Updated"/> yields the 200.
/// </para>
/// </remarks>
/// <param name="credentialId">The §C.3 <c>credentialId</c> the update targets (the 404 key).</param>
/// <param name="entry">The parsed §C.3 <c>credentialStatus</c> entry naming the status list and the bit.</param>
/// <param name="status">The §C.3 <c>status</c>: set the bit when <see langword="true"/>, clear it when <see langword="false"/>.</param>
/// <param name="indexAllocator">The §C.3 <c>indexAllocator</c> (opaque), or <see langword="null"/> when absent.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The §C.3 outcome the endpoint maps to 200 / 404.</returns>
public delegate ValueTask<VcalmStatusUpdateOutcome> UpdateVcalmCredentialStatusDelegate(
    string credentialId,
    BitstringStatusListEntry entry,
    bool status,
    string? indexAllocator,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Persists a status-list credential the VCALM 1.0 §C.1 <c>POST /status-lists</c> endpoint secured,
/// keyed by its <c>id</c>, so the §C.2 <c>GET /status-lists/{id}</c> interface can retrieve it and a
/// later §C.3 update can mutate it. The application owns the store; mirrors
/// <see cref="StoreVcalmIssuedCredentialDelegate"/>.
/// </summary>
/// <param name="statusListId">The status-list credential id to key the stored credential under.</param>
/// <param name="statusListCredentialJson">The verbatim secured status-list-credential JSON to store.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask StoreVcalmStatusListDelegate(
    string statusListId,
    string statusListCredentialJson,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a status-list credential the §C.2 <c>GET /status-lists/{id}</c> endpoint retrieves by id, or
/// <see langword="null"/> when no record exists (§C.2 404). Returns the verbatim secured
/// status-list-credential JSON (a Data Integrity VC object or an
/// <c>EnvelopedVerifiableCredential</c>). §C.2 is "typically publicly accessible without
/// authentication" (the §C privacy guidance prefers holders carrying the list over verifiers
/// phoning home). The application owns the store; mirrors <see cref="LoadVcalmIssuedCredentialDelegate"/>.
/// </summary>
/// <param name="statusListId">The status-list id (the §C.2 <c>{id}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The verbatim status-list-credential JSON, or <see langword="null"/> when the store holds no record.</returns>
public delegate ValueTask<string?> LoadVcalmStatusListDelegate(
    string statusListId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves the decoded W3C Bitstring Status List a verified credential's
/// <see cref="BitstringStatusListEntry"/> points at, so the VCALM 1.0 §3.3.1 / §3.3.2 verifier can
/// read the credential's status bit and classify a revoked / suspended status as a §3.8.1 WARNING.
/// </summary>
/// <remarks>
/// <para>
/// The application composes the resolve-and-decode behind this seam: dereference the entry's
/// <c>statusListCredential</c> URL (through the SSRF-policed <c>OutboundFetch</c> when remote, or the
/// §C.2 store when local), verify the status-list credential's own proof, then decode its
/// <c>encodedList</c> via <see cref="BitstringStatusListCodec.DecodeList"/> and return the resulting
/// <see cref="StatusList"/> plus the purpose(s) the list declares. The library then reads the bit via
/// <see cref="BitstringStatusListValidation.GetStatus(BitstringStatusListEntry, StatusList, System.Collections.Generic.IReadOnlyCollection{string}, System.DateTimeOffset, System.DateTimeOffset?, System.DateTimeOffset?)"/>.
/// </para>
/// <para>
/// The §C privacy guidance prefers the holder supplying the status list in the presentation over the
/// verifier querying the status service ("To maximize privacy, verifiers are encouraged to obtain
/// status information from holders rather than directly querying the status service"). A deployment
/// that follows that guidance backs this seam with the holder-supplied list rather than a fetch.
/// Returning <see langword="null"/> means the status could not be resolved; the verifier then emits
/// no status warning (an undeterminable status is not asserted as revoked).
/// </para>
/// </remarks>
/// <param name="entry">The verified credential's status entry naming the status list, index, and purpose.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity and SSRF policy.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The resolved status list, or <see langword="null"/> when the status could not be resolved.</returns>
public delegate ValueTask<VcalmResolvedStatusList?> ResolveVcalmStatusListDelegate(
    BitstringStatusListEntry entry,
    ExchangeContext context,
    CancellationToken cancellationToken);
