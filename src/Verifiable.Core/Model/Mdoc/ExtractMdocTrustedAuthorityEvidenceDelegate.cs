using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Extracts the OID4VP 1.0 §6.1.1 trust evidence an mdoc IssuerAuth's certificate chain attests to —
/// the <see cref="TrustedAuthorityEvidence"/> a DCQL <c>trusted_authorities</c> constraint on an
/// <c>mso_mdoc</c> credential is matched against.
/// </summary>
/// <remarks>
/// Compose one with <c>Verifiable.Cbor.Mdoc.MdocCborTrustedAuthorityEvidence.Create</c>, mirroring how
/// <c>MdocCborIacaTrustResolver.Create</c> composes the <see cref="ResolveMdocIssuerKeyDelegate"/> —
/// both pull the x5chain out of the IssuerAuth COSE_Sign1 unprotected header and hand the X.509 work
/// to an application-wired delegate. Asynchronous because resolving the <c>etsi_tl</c>/<c>openid_federation</c>
/// arms of the composed <see cref="ResolveTrustedAuthorityEvidenceDelegate"/> can require I/O.
/// </remarks>
/// <param name="issuerAuth">The parsed IssuerAuth whose x5chain supplies the evidence.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The resolved evidence, or <see langword="null"/> when the IssuerAuth carries no x5chain and the resolver yields no other evidence.</returns>
public delegate ValueTask<TrustedAuthorityEvidence?> ExtractMdocTrustedAuthorityEvidenceDelegate(
    MdocIssuerAuth issuerAuth,
    CancellationToken cancellationToken);
