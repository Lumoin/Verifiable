using Verifiable.Core;

namespace Verifiable.Vcalm;

/// <summary>
/// Parses a VCALM 1.0 §3.3.1 <c>POST /credentials/verify</c> request body into the neutral
/// <see cref="VcalmVerifyCredentialRequest"/>. The default <c>System.Text.Json</c> implementation
/// lives in <c>Verifiable.Json</c> and is wired by the application — the <c>Verifiable.Vcalm</c>
/// serialization firewall keeps STJ out of the library, the same way every request body the
/// library parses crosses a parse seam rather than a direct STJ dependency.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object, omits the REQUIRED <c>verifiableCredential</c>,
/// carries an unrecognized top-level member, or carries an unrecognized <c>options</c> member is
/// returned as the corresponding <see cref="VcalmParseFailure"/> rather than thrown — the endpoint
/// maps the failure to the §3.3.1 / §2.4 HTTP outcome. Returns <see langword="null"/> only when the
/// parser cannot proceed at all (it should always return a request, using the static failure
/// factories for rejection).
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmVerifyCredentialRequest?> ParseVcalmVerifyCredentialDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a VCALM 1.0 §3.3.2 <c>POST /presentations/verify</c> request body into the neutral
/// <see cref="VcalmVerifyPresentationRequest"/>. The default implementation lives in
/// <c>Verifiable.Json</c>; same strict-parse contract as
/// <see cref="ParseVcalmVerifyCredentialDelegate"/>.
/// </summary>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmVerifyPresentationRequest?> ParseVcalmVerifyPresentationDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Persists a challenge the VCALM 1.0 §3.3.3 <c>POST /challenges</c> endpoint minted, so a later
/// §3.3.2 <c>/presentations/verify</c> call can check the presentation's <c>options.challenge</c>
/// against the set of issued challenges. The application owns the store; mirrors the
/// <c>PersistJtiDelegate</c> shape.
/// </summary>
/// <remarks>
/// §3.3.3: "The instance should create a challenge for use during verification, and track the
/// number of times the challenge has been passed to verification endpoints as options.challenge."
/// The library mints the challenge value and asks the application to persist it; the application
/// scopes the store however its deployment requires (per-tenant, with a TTL, etc.).
/// </remarks>
/// <param name="challenge">The minted challenge value to persist as issued.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask PersistVcalmChallengeDelegate(
    string challenge,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Consumes a challenge presented on a VCALM 1.0 §3.3.2 <c>/presentations/verify</c> call: returns
/// whether the value was previously issued (and records its use per §3.3.3). The application owns
/// the store; mirrors the <c>IsJtiSeenDelegate</c> shape (inverted sense — here <see langword="true"/>
/// means "recognized and accepted").
/// </summary>
/// <remarks>
/// When the verifier deployment wires both this and <see cref="PersistVcalmChallengeDelegate"/>, the
/// §3.3.2 endpoint enforces that a presented <c>options.challenge</c> was minted by this instance
/// (returning false rejects an unissued / replayed challenge). When the pair is unwired, the
/// challenge is treated as caller-supplied and is matched against the presentation proof only — the
/// instance does not gate on issuance.
/// </remarks>
/// <param name="challenge">The challenge value the presentation proof carried.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns><see langword="true"/> when the challenge was previously issued by this instance.</returns>
public delegate ValueTask<bool> ConsumeVcalmChallengeDelegate(
    string challenge,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a VCALM 1.0 §3.2.1 <c>POST /credentials/issue</c> request body into the neutral
/// <see cref="VcalmIssueCredentialRequest"/>. The default <c>System.Text.Json</c> implementation
/// lives in <c>Verifiable.Json</c> and is wired by the application — same serialization-firewall and
/// strict-parse contract as <see cref="ParseVcalmVerifyCredentialDelegate"/>.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object, omits the REQUIRED <c>credential</c>, carries
/// an unrecognized top-level member, or carries an unrecognized <c>options</c> member is returned as
/// the corresponding <see cref="VcalmParseFailure"/> rather than thrown — the endpoint maps the
/// failure to the §3.2.1 / §2.4 HTTP outcome.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmIssueCredentialRequest?> ParseVcalmIssueCredentialDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Persists a credential the VCALM 1.0 §3.2.1 <c>POST /credentials/issue</c> endpoint secured, keyed
/// by its <c>credentialId</c>, so the §3.2.2 <c>GET /credentials/{id}</c> and §3.2.3
/// <c>DELETE /credentials/{id}</c> interfaces can retrieve and delete it. The application owns the
/// store; mirrors the flow-state Save seam shape.
/// </summary>
/// <remarks>
/// Optional — when unwired the §3.2.1 endpoint still issues and returns the secured credential but
/// the instance does not retain it (a stateless issuer; the §3.2.2 / §3.2.3 MAY interfaces are then
/// absent). The credential id may be absent (§3.2.1: neither <c>credentialId</c> nor
/// <c>credential.id</c> was supplied — "it will not be possible to refer to this credential once
/// issued"); the endpoint only invokes this seam when an id is present.
/// </remarks>
/// <param name="credentialId">The credential id to key the stored credential under.</param>
/// <param name="securedCredentialJson">The verbatim secured-credential JSON to store.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask StoreVcalmIssuedCredentialDelegate(
    string credentialId,
    string securedCredentialJson,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a credential the §3.2.2 <c>GET /credentials/{id}</c> endpoint retrieves by id, or
/// <see langword="null"/> when no record exists (§3.2.2 404). A record whose
/// <see cref="VcalmStoredCredential.IsDeleted"/> is set is the §3.2.2 410-Gone tombstone. The
/// application owns the store; mirrors the flow-state Load seam shape.
/// </summary>
/// <param name="credentialId">The credential id (the §3.2.2 <c>{id}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The stored credential, or <see langword="null"/> when the store holds no record for the id.</returns>
public delegate ValueTask<VcalmStoredCredential?> LoadVcalmIssuedCredentialDelegate(
    string credentialId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Soft-deletes a credential for the §3.2.3 <c>DELETE /credentials/{id}</c> endpoint, returning
/// whether a record existed to delete (false → §3.2.3 404). §3.2.3 defaults to a 202 because "soft
/// deletes and processing time are assumed"; B.3 governs what deletion does to the underlying record
/// and any status side-effects (partial vs complete deletion, revocation / suspension bits) — that
/// is the application's concern behind this seam, not the library's. The application owns the store.
/// </summary>
/// <param name="credentialId">The credential id (the §3.2.3 <c>{id}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns><see langword="true"/> when a record existed and was (soft-)deleted; <see langword="false"/> when none existed.</returns>
public delegate ValueTask<bool> DeleteVcalmIssuedCredentialDelegate(
    string credentialId,
    ExchangeContext context,
    CancellationToken cancellationToken);
