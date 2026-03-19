using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Parses a decrypted VP token, verifies cryptographic signatures, and extracts
/// credential claims. The library validates the extracted values using
/// <see cref="Validation.ValidationChecks"/> via <see cref="Core.Assessment.ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// The implementation is responsible for:
/// </para>
/// <list type="bullet">
///   <item><description>Parsing the SD-JWT VC or mdoc structure.</description></item>
///   <item><description>Verifying the KB-JWT signature and extracting its claims.</description></item>
///   <item><description>Verifying the credential issuer signature.</description></item>
///   <item><description>Computing and verifying <c>sd_hash</c> (SD-JWT) or session transcript (mdoc).</description></item>
///   <item><description>Extracting disclosed credential claims keyed by DCQL query identifier.</description></item>
/// </list>
/// <para>
/// The implementation does NOT decide whether the token is valid — it reports what it
/// found. The executor constructs a <see cref="Validation.ValidationContext"/> from the
/// returned <see cref="VpTokenParsed"/> and runs the configured
/// <see cref="Core.Assessment.ClaimIssuer{TInput}"/> to make that decision.
/// </para>
/// </remarks>
/// <param name="vpTokenJson">The decrypted VP token JSON.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The parsed and crypto-verified VP token contents.</returns>
public delegate ValueTask<VpTokenParsed> ParseVpTokenDelegate(
    string vpTokenJson,
    RequestContext context,
    CancellationToken cancellationToken);
