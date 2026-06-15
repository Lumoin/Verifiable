using Verifiable.Core;

namespace Verifiable.Vcalm;

/// <summary>
/// Parses a VCALM 1.0 §3.5.1 <c>POST /credentials/derive</c> request body into the neutral
/// <see cref="VcalmDeriveCredentialRequest"/>. The default <c>System.Text.Json</c> implementation
/// lives in <c>Verifiable.Json</c> and is wired by the application — the <c>Verifiable.Vcalm</c>
/// serialization firewall keeps STJ out of the library, the same way every request body the library
/// parses crosses a parse seam.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object, omits the REQUIRED <c>verifiableCredential</c>,
/// carries an unrecognized top-level member, or carries an unrecognized <c>options</c> member is
/// returned as the corresponding <see cref="VcalmParseFailure"/> rather than thrown — the endpoint
/// maps the failure to the §3.5.1 / §2.4 HTTP outcome.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmDeriveCredentialRequest?> ParseVcalmDeriveCredentialDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a VCALM 1.0 §3.5.2 <c>POST /presentations</c> request body into the neutral
/// <see cref="VcalmCreatePresentationRequest"/>. The default implementation lives in
/// <c>Verifiable.Json</c>; same strict-parse contract as
/// <see cref="ParseVcalmDeriveCredentialDelegate"/>.
/// </summary>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmCreatePresentationRequest?> ParseVcalmCreatePresentationDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Persists a presentation the VCALM 1.0 §3.5.2 <c>POST /presentations</c> endpoint secured, keyed by
/// its id, so the §3.5.3 <c>GET /presentations</c>, §3.5.4 <c>GET /presentations/{id}</c>, and §3.5.5
/// <c>DELETE /presentations/{id}</c> interfaces can list, retrieve, and delete it. The application
/// owns the store; mirrors the §3.2.1 issued-credential store seam shape.
/// </summary>
/// <remarks>
/// Optional — when unwired the §3.5.2 endpoint still creates and returns the secured presentation but
/// the instance does not retain it (a stateless holder; the §3.5.3 / §3.5.4 / §3.5.5 MAY interfaces are
/// then absent).
/// </remarks>
/// <param name="presentationId">The presentation id to key the stored presentation under.</param>
/// <param name="securedPresentationJson">The verbatim secured-presentation JSON to store.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask StoreVcalmPresentationDelegate(
    string presentationId,
    string securedPresentationJson,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Lists the stored presentations the §3.5.3 <c>GET /presentations</c> endpoint returns — the verbatim
/// secured-presentation JSON of each non-deleted record. The application owns the store and scopes the
/// list to the request's tenant. An empty list is a valid §3.5.3 200 response.
/// </summary>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The verbatim secured-presentation JSON strings, one per non-deleted stored presentation.</returns>
public delegate ValueTask<IReadOnlyList<string>> ListVcalmPresentationsDelegate(
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a presentation the §3.5.4 <c>GET /presentations/{id}</c> endpoint retrieves by id, or
/// <see langword="null"/> when no record exists (§3.5.4 404). A record whose
/// <see cref="VcalmStoredPresentation.IsDeleted"/> is set is the §3.5.4 410-Gone tombstone. The
/// application owns the store; mirrors the §3.2.2 issued-credential load seam shape.
/// </summary>
/// <param name="presentationId">The presentation id (the §3.5.4 <c>{id}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The stored presentation, or <see langword="null"/> when the store holds no record for the id.</returns>
public delegate ValueTask<VcalmStoredPresentation?> LoadVcalmPresentationDelegate(
    string presentationId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Soft-deletes a presentation for the §3.5.5 <c>DELETE /presentations/{id}</c> endpoint, returning
/// whether a record existed to delete (false → §3.5.5 404). §3.5.5 defaults to a 202 because "soft
/// deletes and processing time are assumed"; B.3 governs what deletion does to the underlying record —
/// that is the application's concern behind this seam. The application owns the store.
/// </summary>
/// <param name="presentationId">The presentation id (the §3.5.5 <c>{id}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns><see langword="true"/> when a record existed and was (soft-)deleted; <see langword="false"/> when none existed.</returns>
public delegate ValueTask<bool> DeleteVcalmPresentationDelegate(
    string presentationId,
    ExchangeContext context,
    CancellationToken cancellationToken);
