using System.Buffers;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Default <see cref="ExtractMdocAuthorityIdentifierDelegate"/> factory — composes
/// <see cref="MdocCborX5ChainExtractor"/> with a caller-supplied
/// <see cref="ExtractAuthorityKeyIdentifierDelegate"/> to surface the leaf certificate's
/// AuthorityKeyIdentifier (base64url) for DCQL <c>trusted_authorities</c> enforcement of
/// type <c>aki</c> (OID4VP 1.0 §6.1.1.1).
/// </summary>
/// <remarks>
/// <para>
/// The CBOR twin of <see cref="MdocCborIacaTrustResolver"/>: pulling the x5chain out of the
/// IssuerAuth COSE_Sign1 unprotected header is CBOR work and lives here; reading the X.509
/// AuthorityKeyIdentifier stays behind the <see cref="ExtractAuthorityKeyIdentifierDelegate"/>
/// the application wires (e.g.
/// <c>Verifiable.Microsoft.MicrosoftX509Functions.GetAuthorityKeyIdentifier</c>), so this
/// class carries no X.509 dependency — the same split the trust resolver uses for chain
/// validation.
/// </para>
/// </remarks>
public static class MdocCborAuthorityIdentifierExtractor
{
    /// <summary>
    /// Builds an <see cref="ExtractMdocAuthorityIdentifierDelegate"/> from the supplied
    /// dependencies. The returned delegate is safe to reuse across many extractions — it
    /// captures the dependencies by reference. It returns <see langword="null"/> when the
    /// IssuerAuth has no <c>x5chain</c>, or whatever
    /// <paramref name="extractAuthorityKeyIdentifier"/> returns for the leaf certificate
    /// (itself <see langword="null"/> when the leaf has no AuthorityKeyIdentifier).
    /// </summary>
    /// <param name="extractAuthorityKeyIdentifier">
    /// Reads the leaf certificate's AuthorityKeyIdentifier as base64url (typically
    /// <c>MicrosoftX509Functions.GetAuthorityKeyIdentifier</c>).
    /// </param>
    /// <param name="base64UrlEncoder">The base64url encoder passed through to <paramref name="extractAuthorityKeyIdentifier"/>.</param>
    /// <param name="pool">Memory pool for the DER carriers the x5chain extraction allocates.</param>
    /// <returns>The composed delegate.</returns>
    public static ExtractMdocAuthorityIdentifierDelegate Create(
        ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(extractAuthorityKeyIdentifier);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        return issuerAuth =>
        {
            ArgumentNullException.ThrowIfNull(issuerAuth);

            IReadOnlyList<PkiCertificateMemory> chain = MdocCborX5ChainExtractor.Extract(
                issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), pool);
            try
            {
                return chain.Count == 0
                    ? null
                    : extractAuthorityKeyIdentifier(chain[0], base64UrlEncoder);
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
