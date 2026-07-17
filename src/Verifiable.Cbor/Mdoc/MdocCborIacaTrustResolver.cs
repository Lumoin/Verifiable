using System.Buffers;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Default <see cref="ResolveMdocIssuerKeyDelegate"/> factory — composes
/// <see cref="MdocCborX5ChainExtractor"/> with a caller-supplied
/// <see cref="ValidateCertificateChainAsyncDelegate"/> and trust-anchor list to
/// produce a delegate the wallet/verifier can hand to
/// <see cref="MdocCborIssuerAuthVerifier.VerifyAsync(MdocIssuerAuth, ResolveMdocIssuerKeyDelegate, System.Threading.CancellationToken)"/>.
/// </summary>
/// <remarks>
/// <para>
/// The composition pattern matches the SD-* extension points: the wallet
/// binds the chain validator (typically
/// <c>MicrosoftX509Functions.ValidateChainAsync</c>) and the trust anchors
/// (loaded from the EUDI IACA trust list or equivalent), then plugs the
/// resulting delegate into the verifier's trust-then-verify call.
/// </para>
/// <para>
/// Failure semantics:
/// </para>
/// <list type="bullet">
///   <item><description>
///     No <c>x5chain</c> in the unprotected header →
///     <see cref="MdocIacaTrustFailureReason.X5ChainHeaderMissing"/>.
///   </description></item>
///   <item><description>
///     Malformed <c>x5chain</c> value →
///     <see cref="MdocIacaTrustFailureReason.X5ChainMalformed"/>.
///   </description></item>
///   <item><description>
///     Chain validator throws → <see cref="MdocIacaTrustFailureReason.ChainValidationFailed"/>;
///     the exception's message is preserved in
///     <see cref="MdocIacaTrustResolution.FailureMessage"/>.
///   </description></item>
///   <item><description>
///     Leaf key extraction throws (unsupported curve / kty inside the cert) →
///     <see cref="MdocIacaTrustFailureReason.LeafKeyExtractionFailed"/>.
///   </description></item>
/// </list>
/// </remarks>
public static class MdocCborIacaTrustResolver
{
    /// <summary>
    /// Builds a <see cref="ResolveMdocIssuerKeyDelegate"/> from the
    /// supplied dependencies. The returned delegate is safe to reuse across
    /// many resolutions — it captures the dependencies by reference.
    /// </summary>
    /// <param name="validateChain">
    /// The chain-validation function (typically
    /// <c>MicrosoftX509Functions.ValidateChainAsync</c>).
    /// </param>
    /// <param name="trustAnchors">
    /// The IACA trust anchors the validator builds against. Caller
    /// retains ownership; do not dispose them while the delegate is in use.
    /// </param>
    /// <param name="validationTime">
    /// The instant for certificate-validity evaluation. Production callers
    /// pass <c>DateTimeOffset.UtcNow</c>; tests pass deterministic times.
    /// </param>
    /// <param name="pool">Memory pool for DER and key-material allocations.</param>
    /// <returns>The composed delegate.</returns>
    public static ResolveMdocIssuerKeyDelegate Create(
        ValidateCertificateChainAsyncDelegate validateChain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);

        return async (issuerAuth, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(issuerAuth);

            IReadOnlyList<PkiCertificateMemory>? chain = null;
            try
            {
                chain = MdocCborX5ChainExtractor.Extract(issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), pool);

                if(chain.Count == 0)
                {
                    return MdocIacaTrustResolution.Failed(
                        MdocIacaTrustFailureReason.X5ChainHeaderMissing);
                }

                PublicKeyMemory leafKey;
                try
                {
                    leafKey = await validateChain(
                        chain, trustAnchors, validationTime, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                }
                catch(System.Security.SecurityException ex)
                {
                    return MdocIacaTrustResolution.Failed(
                        MdocIacaTrustFailureReason.ChainValidationFailed, ex.Message);
                }
                catch(NotSupportedException ex)
                {
                    return MdocIacaTrustResolution.Failed(
                        MdocIacaTrustFailureReason.LeafKeyExtractionFailed, ex.Message);
                }

                return MdocIacaTrustResolution.Success(leafKey);
            }
            catch(System.Formats.Cbor.CborContentException ex)
            {
                return MdocIacaTrustResolution.Failed(
                    MdocIacaTrustFailureReason.X5ChainMalformed, ex.Message);
            }
            finally
            {
                if(chain is not null)
                {
                    foreach(PkiCertificateMemory cert in chain)
                    {
                        cert.Dispose();
                    }
                }
            }
        };
    }
}
