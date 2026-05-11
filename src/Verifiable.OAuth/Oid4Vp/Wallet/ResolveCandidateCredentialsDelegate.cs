using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Returns the wallet-held credentials that satisfy a DCQL query.
/// </summary>
/// <remarks>
/// The wallet client calls this delegate once per presentation to obtain the
/// candidate credentials for the inbound JAR's <c>dcql_query</c>. Applications
/// implement it against their credential store — in-memory, encrypted-at-rest,
/// hardware-backed, etc. — and may apply any storage-side filtering they like
/// before returning the candidate list.
/// </remarks>
/// <typeparam name="TCredential">
/// The application-supplied credential type. For SD-JWT VC use
/// <see cref="SdJwtVcCredential"/> or a derived type.
/// </typeparam>
/// <param name="query">The parsed DCQL query from the inbound JAR.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The candidate credentials matching the query.</returns>
public delegate ValueTask<IReadOnlyList<TCredential>> ResolveCandidateCredentialsDelegate<TCredential>(
    DcqlQuery query,
    CancellationToken cancellationToken);
