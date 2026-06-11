using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The application-supplied seam that OPTS IN to library-side resolution of the OID4VCI 1.0
/// Appendix F.1 <c>x5c</c> key-reference mode of a <c>jwt</c> key proof. Carried on
/// <see cref="CredentialProofExpectation.X509Verification"/>; when it is <see langword="null"/> a
/// proof that references its key by <c>x5c</c> cannot be resolved and is rejected as
/// <c>invalid_proof</c> (<see cref="CredentialProofValidationFailureReason.KeyReferenceUnresolved"/>),
/// while the embedded-<c>jwk</c> and <c>kid</c> modes are unaffected.
/// </summary>
/// <remarks>
/// <para>
/// Appendix F.1: "x5c: OPTIONAL. JOSE Header containing at least one certificate where the first
/// certificate contains the key that the Credential is to be bound to, additional certificates may
/// also be present." The library does not re-roll the X.509 surface: it composes the SAME
/// <see cref="ParseX5cDelegate"/> and <see cref="ValidateCertificateChainAsyncDelegate"/> platform
/// functions the OID4VP <c>x509_san_dns:</c> / <c>x509_hash:</c> JAR-key resolvers
/// (<see cref="Oid4Vp.X509SanDnsKeyResolver"/>, <see cref="Oid4Vp.X509HashKeyResolver"/>) compose —
/// parse the base64-DER chain, validate it to the trust anchors, extract the leaf public key.
/// </para>
/// <para>
/// Unlike the OID4VP JAR case, a key proof carries no client-id DNS/hash binding: the <c>x5c</c>
/// simply provides the holder's certificate, so only the parse + chain-validate + leaf-key steps
/// apply. The chain is validated to trust anchors as an issuer-policy seam: the application supplies
/// the anchors and the validity instant on the threaded
/// <see cref="Verifiable.Core.ExchangeContext"/> through
/// <see cref="Oid4Vp.Oid4VpExchangeContextExtensions.SetX509TrustAnchors(Verifiable.Core.ExchangeContext, System.Collections.Generic.IReadOnlyList{PkiCertificateMemory})"/>
/// and <see cref="Verifiable.Core.ExchangeContextExtensions.SetValidationTime(Verifiable.Core.ExchangeContext, System.DateTimeOffset)"/>,
/// exactly as the OID4VP x509 handlers read <c>context.X509TrustAnchors</c> — so one wired
/// verification serves every tenant with no captured trust material.
/// </para>
/// </remarks>
public sealed record Oid4VciProofX509Verification
{
    /// <summary>
    /// Parses the base64-DER certificate strings of the <c>x5c</c> JOSE header into the chain
    /// (leaf first per RFC 7515 §4.1.6). The same platform function the OID4VP x509 resolvers use.
    /// </summary>
    public required ParseX5cDelegate ParseX5c { get; init; }

    /// <summary>
    /// Validates the parsed chain to the context's trust anchors at the context's validation time
    /// and extracts the leaf certificate's public key — the holder key the §F.4 signature check
    /// runs against. The same platform function the OID4VP x509 resolvers use.
    /// </summary>
    public required ValidateCertificateChainAsyncDelegate ValidateChain { get; init; }

    /// <summary>The memory pool backing the transient certificate / key buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}
