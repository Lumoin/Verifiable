using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.OAuth.Federation;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// OID4VP-layer typed accessors for the per-tenant trust material a
/// <see cref="ResolveClientIdSigningKeyAsyncDelegate"/> handler reads off the
/// threaded <see cref="ExchangeContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// The composite client-id key-resolver handlers
/// (<see cref="CompositeClientIdSigningKeyResolver"/>) are <em>stateless</em>:
/// they capture no trust anchors. A single registered handler set serves every
/// tenant in a recursive multi-tenant deployment because the per-operation
/// <see cref="ExchangeContext"/> carries the trust material the current tenant's
/// operation should be evaluated against. The application places that material
/// here — keyed by tenant in whatever way its own storage dictates — before
/// driving the presentation; the library handler reads it back through these
/// accessors with no closure capture (see <c>feedback_no_closure_capture</c>).
/// </para>
/// <para>
/// The cert/statement <em>algorithm</em> delegates (x5c parse, chain validation,
/// DNS-SAN check, trust-chain validation) remain explicit handler-builder
/// parameters: they are stateless platform functions, not per-tenant data, so
/// capturing them is the established pattern. Only the trust anchors — the data
/// that varies by tenant — flow through the context.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Oid4VpExchangeContextExtensions
{
    private const string X509TrustAnchorsKey = "oid4vp.x509TrustAnchors";
    private const string OpenIdFederationTrustAnchorsKey = "oid4vp.openIdFederationTrustAnchors";
    private const string VerifierAttestationTrustAnchorKeyKey = "oid4vp.verifierAttestationTrustAnchorKey";


    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the X.509 trust-anchor certificates the <c>x509_san_dns:</c>
        /// handler validates the JAR's <c>x5c</c> chain against, or
        /// <see langword="null"/> when the application has not placed any on
        /// this context.
        /// </summary>
        public IReadOnlyList<PkiCertificateMemory>? X509TrustAnchors =>
            context.TryGetValue(X509TrustAnchorsKey, out object? value)
                && value is IReadOnlyList<PkiCertificateMemory> anchors ? anchors : null;

        /// <summary>
        /// Sets the X.509 trust-anchor certificates for the current operation's
        /// tenant. The application owns the certificates' lifetime; the handler
        /// does not dispose them.
        /// </summary>
        /// <param name="trustAnchors">The trust-anchor certificates.</param>
        public void SetX509TrustAnchors(IReadOnlyList<PkiCertificateMemory> trustAnchors)
        {
            ArgumentNullException.ThrowIfNull(trustAnchors);
            context[X509TrustAnchorsKey] = trustAnchors;
        }


        /// <summary>
        /// Gets the OpenID Federation trust-anchor entity identifiers the
        /// <c>openid_federation:</c> handler validates the inline
        /// <c>trust_chain</c> against, or <see langword="null"/> when none are
        /// present on this context.
        /// </summary>
        public IReadOnlyCollection<EntityIdentifier>? OpenIdFederationTrustAnchors =>
            context.TryGetValue(OpenIdFederationTrustAnchorsKey, out object? value)
                && value is IReadOnlyCollection<EntityIdentifier> anchors ? anchors : null;

        /// <summary>
        /// Sets the OpenID Federation trust-anchor entity identifiers for the
        /// current operation's tenant.
        /// </summary>
        /// <param name="trustAnchors">The trust-anchor entity identifiers.</param>
        public void SetOpenIdFederationTrustAnchors(IReadOnlyCollection<EntityIdentifier> trustAnchors)
        {
            ArgumentNullException.ThrowIfNull(trustAnchors);
            context[OpenIdFederationTrustAnchorsKey] = trustAnchors;
        }


        /// <summary>
        /// Gets the trust-anchor public key the <c>verifier_attestation:</c>
        /// handler verifies the attestation JWT against, or
        /// <see langword="null"/> when none is present on this context.
        /// </summary>
        public PublicKeyMemory? VerifierAttestationTrustAnchorKey =>
            context.TryGetValue(VerifierAttestationTrustAnchorKeyKey, out object? value)
                && value is PublicKeyMemory key ? key : null;

        /// <summary>
        /// Sets the trust-anchor public key the <c>verifier_attestation:</c>
        /// handler uses for the current operation's tenant. The application owns
        /// the key's lifetime; the handler does not dispose it.
        /// </summary>
        /// <param name="trustAnchorKey">The trust-anchor public key.</param>
        public void SetVerifierAttestationTrustAnchorKey(PublicKeyMemory trustAnchorKey)
        {
            ArgumentNullException.ThrowIfNull(trustAnchorKey);
            context[VerifierAttestationTrustAnchorKeyKey] = trustAnchorKey;
        }
    }
}
