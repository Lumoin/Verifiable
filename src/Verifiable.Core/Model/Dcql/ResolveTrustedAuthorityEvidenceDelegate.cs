using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Resolves a credential's <see cref="TrustedAuthorityEvidence"/> from its certificate chain and
/// issuer identifier — the composition seam that runs the X.509 (<c>aki</c>), ETSI Trusted List
/// (<c>etsi_tl</c>) and OpenID Federation (<c>openid_federation</c>) evidence arms together against
/// the wallet's own held anchors and lists.
/// </summary>
/// <remarks>
/// Asynchronous because the <c>openid_federation</c> arm resolves a trust chain, which is I/O; a
/// caller runs this at credential storage or refresh time, never at request-evaluation time, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
/// OpenID for Verifiable Presentations 1.0, Section 15.10</see>. The cached result then reaches the
/// evaluator through <see cref="TrustedAuthorityEvidenceSource{TCredential}"/>.
/// </remarks>
/// <param name="chain">The credential's certificate chain, leaf first; empty when the credential carries no X.509 chain.</param>
/// <param name="issuerIdentifier">The credential's issuer identifier (an SD-JWT VC <c>iss</c>, say) for the <c>openid_federation</c> arm, or <see langword="null"/> when the credential carries none.</param>
/// <param name="pool">Memory pool for any allocation the resolution performs.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The resolved evidence, or <see langword="null"/> when neither the chain nor the issuer identifier yields any.</returns>
public delegate ValueTask<TrustedAuthorityEvidence?> ResolveTrustedAuthorityEvidenceDelegate(
    IReadOnlyList<PkiCertificateMemory> chain,
    string? issuerIdentifier,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);
