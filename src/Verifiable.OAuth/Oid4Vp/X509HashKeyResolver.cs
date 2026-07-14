using System.Buffers;
using System.Security;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Resolves the Verifier's JAR signing public key from the <c>x5c</c> JOSE header
/// for the <c>x509_hash:</c> Client Identifier Prefix per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see>
/// and the additional constraints of
/// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0 §5.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>x509_hash:</c> prefix binds the <c>client_id</c> to the leaf certificate
/// by digest rather than by DNS SAN (see <see cref="X509SanDnsKeyResolver"/>): the
/// Client Identifier (the part after the prefix) is the base64url-encoded SHA-256
/// hash of the DER-encoded leaf certificate carried in <c>x5c</c>.
/// </para>
/// <para>
/// Beyond chain validation and the hash binding, HAIP 1.0 §5.2 imposes two further
/// constraints on a signed request under this prefix, both enforced here:
/// </para>
/// <list type="number">
///   <item><description>
///     The request-signing (leaf) certificate MUST NOT be self-signed.
///   </description></item>
///   <item><description>
///     The trust anchor certificate MUST NOT be included in the <c>x5c</c> header
///     — it is supplied out-of-band on the <see cref="ExchangeContext"/>.
///   </description></item>
/// </list>
/// <para>
/// The hash algorithm and base64url encoding are supplied as delegates so the
/// platform driver owns the cryptography; OID4VP 1.0 §5.9.3 fixes the algorithm to
/// SHA-256, so the application MUST wire a SHA-256 implementation for
/// <paramref name="hashFunction"/>.
/// </para>
/// </remarks>
public static class X509HashKeyResolver
{
    /// <summary>
    /// Parses and validates the <c>x5c</c> certificate chain, enforces the HAIP 1.0
    /// §5.2 self-signed and trust-anchor-exclusion constraints, verifies the leaf
    /// certificate's SHA-256 hash matches <paramref name="expectedCertificateHash"/>,
    /// and returns the leaf certificate's public key for JAR signature verification.
    /// </summary>
    /// <param name="x5cValues">
    /// The base64-encoded DER certificate strings from the <c>x5c</c> JOSE header.
    /// Leaf certificate first per RFC 7515 §4.1.6.
    /// </param>
    /// <param name="expectedCertificateHash">
    /// The base64url-encoded SHA-256 hash the leaf certificate must produce. This is
    /// the <c>client_id</c> with the <c>x509_hash:</c> prefix stripped.
    /// </param>
    /// <param name="trustAnchors">Trust anchor certificates for chain validation.</param>
    /// <param name="validationTime">The UTC time at which to evaluate certificate validity.</param>
    /// <param name="parseX5c">Delegate for parsing the DER-encoded certificate chain.</param>
    /// <param name="validateChain">Delegate for chain validation and leaf key extraction.</param>
    /// <param name="isSelfSigned">
    /// Neutral predicate reporting whether the leaf certificate is self-signed. The
    /// HAIP 1.0 §5.2 prohibition on a self-signed signing certificate is applied here,
    /// not in the predicate.
    /// </param>
    /// <param name="hashFunction">
    /// Delegate computing the certificate digest. MUST be SHA-256 per OID4VP 1.0 §5.9.3.
    /// </param>
    /// <param name="base64UrlEncoder">Delegate that base64url-encodes the digest (unpadded).</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The leaf certificate's public key. The caller owns the returned
    /// <see cref="PublicKeyMemory"/> and must dispose it.
    /// </returns>
    /// <exception cref="SecurityException">
    /// Thrown when the leaf is self-signed, the trust anchor appears in <c>x5c</c>,
    /// chain validation fails, or the leaf hash does not match.
    /// </exception>
    public static async ValueTask<PublicKeyMemory> ResolveAsync(
        IReadOnlyList<string> x5cValues,
        string expectedCertificateHash,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        ParseX5cDelegate parseX5c,
        ValidateCertificateChainAsyncDelegate validateChain,
        IsSelfSignedCertificateDelegate isSelfSigned,
        HashFunctionDelegate hashFunction,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(x5cValues);
        ArgumentNullException.ThrowIfNull(expectedCertificateHash);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(parseX5c);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(isSelfSigned);
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        IReadOnlyList<PkiCertificateMemory> chain = parseX5c(x5cValues, pool);

        try
        {
            //HAIP 1.0 §5.2: the request-signing (leaf) certificate MUST NOT be
            //self-signed. Checked before chain validation — it is a structural
            //precondition on the submitted certificate, independent of trust. The
            //predicate is neutral; the prohibition is this layer's policy.
            if(isSelfSigned(chain[0]))
            {
                throw new SecurityException(
                    "x509_hash: the request-signing certificate MUST NOT be self-signed (HAIP 1.0 §5.2).");
            }

            //HAIP 1.0 §5.2: the trust anchor certificate MUST NOT be carried in x5c.
            //A byte-for-byte DER comparison is sufficient and needs no parsing.
            foreach(PkiCertificateMemory anchor in trustAnchors)
            {
                foreach(PkiCertificateMemory submitted in chain)
                {
                    if(submitted.AsReadOnlyMemory().Span.SequenceEqual(anchor.AsReadOnlyMemory().Span))
                    {
                        throw new SecurityException(
                            "x509_hash: the trust anchor certificate MUST NOT appear in the x5c JOSE header " +
                            "of the signed request (HAIP 1.0 §5.2).");
                    }
                }
            }

            PublicKeyMemory leafKey = await validateChain(
                chain, trustAnchors, validationTime, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            try
            {
                //OID4VP 1.0 §5.9.3: the stripped client_id MUST equal the base64url-encoded
                //SHA-256 hash of the DER-encoded leaf certificate. The x5c entry IS the DER,
                //so the leaf carrier's bytes are hashed directly — no re-encoding.
                if(!LeafHashMatches(chain[0], expectedCertificateHash, hashFunction, base64UrlEncoder))
                {
                    throw new SecurityException(
                        $"x509_hash: the leaf certificate hash does not match the " +
                        $"client_id hash '{expectedCertificateHash}' (OID4VP 1.0 §5.9.3).");
                }

                return leafKey;
            }
            catch
            {
                leafKey.Dispose();
                throw;
            }
        }
        finally
        {
            foreach(PkiCertificateMemory cert in chain)
            {
                cert.Dispose();
            }
        }
    }


    /// <summary>
    /// Computes the base64url SHA-256 hash of the leaf certificate's DER and compares
    /// it ordinally to the expected hash. Kept synchronous so the <c>stackalloc</c>'d
    /// digest <see cref="Span{T}"/> does not live across an <c>await</c> in the caller.
    /// </summary>
    private static bool LeafHashMatches(
        PkiCertificateMemory leaf,
        string expectedCertificateHash,
        HashFunctionDelegate hashFunction,
        EncodeDelegate base64UrlEncoder)
    {
        ReadOnlySpan<byte> leafDer = leaf.AsReadOnlyMemory().Span;

        //64 bytes covers any SHA-2 output; SHA-256 writes 32. The transient digest lives
        //on the stack only — it is never surfaced as a naked buffer.
        Span<byte> digest = stackalloc byte[64];
        int written = hashFunction(leafDer, digest);

        return string.Equals(
            base64UrlEncoder(digest[..written]), expectedCertificateHash, StringComparison.Ordinal);
    }
}
