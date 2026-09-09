using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Default <see cref="ExtractMdocTrustedAuthorityEvidenceDelegate"/> factory — pulls the FULL
/// <c>x5chain</c> out of an mdoc IssuerAuth's COSE_Sign1 unprotected header and hands it to a
/// <see cref="ResolveTrustedAuthorityEvidenceDelegate"/> to compose the OID4VP 1.0 §6.1.1 evidence.
/// </summary>
/// <remarks>
/// The CBOR twin of <see cref="MdocCborIacaTrustResolver"/>: pulling the x5chain out of the
/// IssuerAuth COSE_Sign1 unprotected header is CBOR work and lives here; composing the AKI/Trusted
/// List/Federation evidence arms stays behind the <see cref="ResolveTrustedAuthorityEvidenceDelegate"/>
/// the application wires, so this class carries no X.509 or Federation dependency — the same split
/// the trust resolver uses for chain validation. mdoc carries no <c>iss</c> claim, so the resolver's
/// issuer-identifier parameter is always <see langword="null"/> here; a validated federation trust
/// path for an mdoc issuer is derived from the chain alone.
/// </remarks>
public static class MdocCborTrustedAuthorityEvidence
{
    /// <summary>
    /// Builds an <see cref="ExtractMdocTrustedAuthorityEvidenceDelegate"/> from the supplied
    /// resolver. The returned delegate is safe to reuse across many extractions — it captures the
    /// resolver and pool by reference. Every certificate in the IssuerAuth's x5chain is extracted
    /// (not the leaf alone) and disposed once the resolver has read them.
    /// </summary>
    /// <param name="resolve">Composes the AKI/Trusted List/Federation evidence arms from a certificate chain.</param>
    /// <param name="pool">Memory pool for the x5chain extraction's DER allocations.</param>
    /// <returns>The composed delegate.</returns>
    public static ExtractMdocTrustedAuthorityEvidenceDelegate Create(
        ResolveTrustedAuthorityEvidenceDelegate resolve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(resolve);
        ArgumentNullException.ThrowIfNull(pool);

        return async (issuerAuth, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(issuerAuth);

            IReadOnlyList<PkiCertificateMemory> chain = CoseSign1X5ChainExtractor.Extract(
                issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), pool);
            try
            {
                return await resolve(chain, issuerIdentifier: null, pool, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                foreach(PkiCertificateMemory cert in chain)
                {
                    cert.Dispose();
                }
            }
        };
    }
}
