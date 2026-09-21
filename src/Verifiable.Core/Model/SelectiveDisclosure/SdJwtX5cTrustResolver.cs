using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The Inline X.509 Certificates mechanism of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#section-2.5">SD-JWT
/// VC draft-19, Section 2.5</see>: "When the protected header of the Issuer-signed JWT contains the
/// x5c parameter, the recipient uses the public key from the end-entity certificate of the
/// certificates from that x5c parameter and validates the X.509 certificate chain accordingly." The
/// SD-JWT sibling of <c>Verifiable.Cbor.Mdoc.MdocCborIacaTrustResolver</c>, composed from the
/// same <see cref="ValidateCertificateChainAsyncDelegate"/> and trust-anchor shape, minus the CBOR
/// <c>x5chain</c> extraction — the SD-JWT header's <c>x5c</c> is already a base64-encoded DER string
/// list by the time it reaches this resolver.
/// </summary>
public static class SdJwtX5cTrustResolver
{
    /// <summary>
    /// Validates an Issuer-signed JWT's <c>x5c</c> header chain and returns the end-entity
    /// certificate's public key, for composing into an application's own issuer-key resolution seam.
    /// </summary>
    /// <param name="x5c">The header's <c>x5c</c> chain (leaf first, per RFC 7515 §4.1.6).</param>
    /// <param name="parseX5c">Parses the <c>x5c</c> header's base64-encoded DER strings into certificates.</param>
    /// <param name="validateChain">
    /// The chain-validation function (typically <c>MicrosoftX509Functions.ValidateChainAsync</c>).
    /// </param>
    /// <param name="trustAnchors">
    /// The trust anchors the validator builds against. Caller retains ownership; do not dispose them
    /// while this call is in flight.
    /// </param>
    /// <param name="validationTime">
    /// The instant for certificate-validity evaluation, read by the caller from its own
    /// <see cref="TimeProvider"/> for this call — never captured across calls, so every resolution is
    /// validated against its own instant rather than a fixed one.
    /// </param>
    /// <param name="pool">Memory pool for DER and key-material allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The end-entity certificate's public key on a chain that validates to one of
    /// <paramref name="trustAnchors"/>, or <see langword="null"/> when the chain is empty or does not
    /// validate — no second chain validator, no metadata fetch. A refused chain's exception is
    /// recorded on <see cref="Activity.Current"/> before this method answers <see langword="null"/>.
    /// </returns>
    public static async ValueTask<PublicKeyMemory?> ResolveAsync(
        IReadOnlyList<string> x5c,
        ParseX5cDelegate parseX5c,
        ValidateCertificateChainAsyncDelegate validateChain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(x5c);
        ArgumentNullException.ThrowIfNull(parseX5c);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);

        if(x5c.Count == 0)
        {
            return null;
        }

        IReadOnlyList<PkiCertificateMemory> chain = parseX5c(x5c, pool);
        try
        {
            return await validateChain(
                chain, trustAnchors, validationTime, pool, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch(System.Security.SecurityException ex)
        {
            _ = (Activity.Current?.AddException(ex));

            return null;
        }
        catch(NotSupportedException ex)
        {
            _ = (Activity.Current?.AddException(ex));

            return null;
        }
        finally
        {
            foreach(PkiCertificateMemory certificate in chain)
            {
                certificate.Dispose();
            }
        }
    }
}
