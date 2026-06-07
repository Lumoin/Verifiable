using System.Buffers;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Validates an inline OpenID Federation 1.0 trust chain: parses each
/// compact JWS into a typed <see cref="EntityStatement"/>, verifies every
/// per-link signature against the appropriate JWKS, runs the chain rules
/// from <see cref="TrustChainValidator"/>, and returns the validation
/// outcome.
/// </summary>
/// <param name="compactJwsChain">
/// The trust_chain JOSE header parameter value (Federation §4.3) — a
/// positional array of compact JWS strings, leaf → trust anchor.
/// </param>
/// <param name="trustAnchors">
/// The application's trust anchor allow-list. A chain validates only if
/// its terminal Entity Configuration's <see cref="EntityStatement.Issuer"/>
/// appears here.
/// </param>
/// <param name="validationTime">
/// The instant against which iat / exp checks are evaluated.
/// </param>
/// <param name="clockSkew">
/// Maximum acceptable clock skew for temporal checks.
/// </param>
/// <param name="pool">
/// Memory pool for transient buffer allocations during parse + verify.
/// </param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// A <see cref="TrustChainValidationOutcome"/> reporting success with the
/// parsed chain + <see cref="Verifiable.Core.Assessment.ClaimIssueResult"/>,
/// or rejection with a typed reason.
/// </returns>
/// <remarks>
/// <para>
/// Pluggable analogue to <see cref="Verifiable.Cryptography.Pki.ValidateCertificateChainDelegate"/>
/// on the X.509 side — same shape, same role. Drivers vary along axes
/// like which JWS verification primitive runs per link, whether
/// statements get reparsed via the source-gen resolver or
/// <see cref="MetadataPolicyParser"/>'s loose-dict path, or whether
/// statements are HTTP-fetched on cache miss.
/// </para>
/// </remarks>
public delegate ValueTask<TrustChainValidationOutcome> ValidateTrustChainAsyncDelegate(
    IReadOnlyList<string> compactJwsChain,
    IReadOnlyCollection<EntityIdentifier> trustAnchors,
    DateTimeOffset validationTime,
    TimeSpan clockSkew,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
