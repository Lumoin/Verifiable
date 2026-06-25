using System.Buffers;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Verifies an OID4VCI 1.0 Appendix D.1 key attestation (<c>key-attestation+jwt</c>): the signature
/// against the Wallet-Provider key its JOSE header references, the <c>exp</c> freshness, and the
/// <c>nonce</c> the Issuer provided. The verifying counterpart of the structural-only
/// <see cref="KeyAttestationParser"/> — it closes the "presence enforced, signature unverifiable" gap
/// where the Credential Endpoint refuses a missing attestation but offered no way to tell a genuine
/// attestation from a forged one.
/// </summary>
/// <remarks>
/// <para>
/// The verifier composes the library's existing primitives rather than re-rolling crypto: the body is
/// parsed with <see cref="KeyAttestationParser"/>, the Wallet-Provider key is resolved through the
/// shared <see cref="Oid4VciHeaderKeyResolution"/> (the same §F.1 <c>jwk</c>/<c>x5c</c>/<c>kid</c>
/// machinery the <c>jwt</c> key-proof validator uses), and the signature is checked with
/// <see cref="Jws.VerifyAsync"/>. The Wallet-Provider trust anchors remain the application's seam: the
/// <c>x5c</c> chain validates to <c>ExchangeContext.X509TrustAnchors</c> and the <c>kid</c> mode is
/// dereferenced by <see cref="Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate"/>.
/// </para>
/// <para>
/// Verification is fail-closed over untrusted input — a malformed attestation yields a
/// <see cref="KeyAttestationVerificationResult"/> carrying a
/// <see cref="KeyAttestationVerificationFailureReason"/>, never a thrown exception.
/// </para>
/// </remarks>
[DebuggerDisplay("KeyAttestationVerifier")]
public static class KeyAttestationVerifier
{
    private static ReadOnlySpan<byte> KidHeaderUtf8 => "kid"u8;
    private static ReadOnlySpan<byte> X5cHeaderUtf8 => "x5c"u8;


    /// <summary>
    /// Resolves the Wallet-Provider public key an attestation's <c>kid</c> JOSE header names — the
    /// reference mode that identifies the Wallet Provider's signing key the deployment dereferences
    /// against its own trust (a Wallet-Provider metadata key set, a DID URL, or a key store). The
    /// <c>jwk</c> mode is self-contained and the <c>x5c</c> mode is resolved by the library; only this
    /// mode is a deployment seam. Returning <see langword="null"/> means the key could not be resolved
    /// and the attestation is rejected.
    /// </summary>
    /// <param name="kid">The attestation's <c>kid</c> JOSE header value to dereference.</param>
    /// <param name="algorithm">The attestation's <c>alg</c> header value.</param>
    /// <param name="context">The per-request context threaded to a network-resolving <c>kid</c> for its SSRF policy.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolved Wallet-Provider public key, or <see langword="null"/> when unresolved.</returns>
    public delegate ValueTask<PublicKeyMemory?> ResolveWalletProviderKeyDelegate(
        string kid,
        string algorithm,
        ExchangeContext context,
        CancellationToken cancellationToken);


    /// <summary>
    /// Verifies a key attestation, resolving the signature-verification function from the registered
    /// cryptographic backends keyed on the resolved Wallet-Provider key's algorithm.
    /// </summary>
    /// <param name="compactAttestation">The compact <c>key-attestation+jwt</c>.</param>
    /// <param name="expectedNonce">The <c>nonce</c> the Issuer provided that the attestation must echo, or <see langword="null"/> when none was issued.</param>
    /// <param name="nonceRequired">Whether a <c>nonce</c> is required (the Issuer supplied one).</param>
    /// <param name="isAttestationSigningAlgAcceptable">Predicate deciding whether the attestation's <c>alg</c> is acceptable per the application's policy.</param>
    /// <param name="resolveWalletProviderKey">Resolves the Wallet-Provider key for the <c>kid</c> reference mode, or <see langword="null"/> when that mode is unsupported.</param>
    /// <param name="x509Verification">Resolves the Wallet-Provider key for the <c>x5c</c> reference mode, or <see langword="null"/> when that mode is unsupported.</param>
    /// <param name="context">The per-request context carrying the <c>x5c</c> trust anchors / validity instant and the SSRF policy.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the JWS segments and JWK coordinates.</param>
    /// <param name="timeProvider">The clock the <c>exp</c> check is measured against.</param>
    /// <param name="memoryPool">Memory pool for the transient decode/verify buffers.</param>
    /// <param name="clockSkew">The leniency added to <c>exp</c> before treating the attestation as expired.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result carrying the verified attestation on success.</returns>
    public static ValueTask<KeyAttestationVerificationResult> VerifyAsync(
        string compactAttestation,
        string? expectedNonce,
        bool nonceRequired,
        Func<string, bool> isAttestationSigningAlgAcceptable,
        ResolveWalletProviderKeyDelegate? resolveWalletProviderKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan clockSkew,
        CancellationToken cancellationToken) =>
        VerifyCoreAsync(
            compactAttestation,
            expectedNonce,
            nonceRequired,
            verificationDelegate: null,
            isAttestationSigningAlgAcceptable,
            Adapt(resolveWalletProviderKey),
            x509Verification,
            context,
            base64UrlDecoder,
            timeProvider,
            memoryPool,
            clockSkew,
            cancellationToken);


    /// <summary>
    /// Verifies a key attestation using an explicit <paramref name="verificationDelegate"/> for the
    /// signature step.
    /// </summary>
    /// <param name="compactAttestation">The compact <c>key-attestation+jwt</c>.</param>
    /// <param name="expectedNonce">The <c>nonce</c> the Issuer provided that the attestation must echo, or <see langword="null"/> when none was issued.</param>
    /// <param name="nonceRequired">Whether a <c>nonce</c> is required (the Issuer supplied one).</param>
    /// <param name="verificationDelegate">The signature-verification function for the attestation's algorithm.</param>
    /// <param name="isAttestationSigningAlgAcceptable">Predicate deciding whether the attestation's <c>alg</c> is acceptable per the application's policy.</param>
    /// <param name="resolveWalletProviderKey">Resolves the Wallet-Provider key for the <c>kid</c> reference mode, or <see langword="null"/> when that mode is unsupported.</param>
    /// <param name="x509Verification">Resolves the Wallet-Provider key for the <c>x5c</c> reference mode, or <see langword="null"/> when that mode is unsupported.</param>
    /// <param name="context">The per-request context carrying the <c>x5c</c> trust anchors / validity instant and the SSRF policy.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the JWS segments and JWK coordinates.</param>
    /// <param name="timeProvider">The clock the <c>exp</c> check is measured against.</param>
    /// <param name="memoryPool">Memory pool for the transient decode/verify buffers.</param>
    /// <param name="clockSkew">The leniency added to <c>exp</c> before treating the attestation as expired.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result carrying the verified attestation on success.</returns>
    public static ValueTask<KeyAttestationVerificationResult> VerifyAsync(
        string compactAttestation,
        string? expectedNonce,
        bool nonceRequired,
        VerificationDelegate verificationDelegate,
        Func<string, bool> isAttestationSigningAlgAcceptable,
        ResolveWalletProviderKeyDelegate? resolveWalletProviderKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan clockSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verificationDelegate);

        return VerifyCoreAsync(
            compactAttestation,
            expectedNonce,
            nonceRequired,
            verificationDelegate,
            isAttestationSigningAlgAcceptable,
            Adapt(resolveWalletProviderKey),
            x509Verification,
            context,
            base64UrlDecoder,
            timeProvider,
            memoryPool,
            clockSkew,
            cancellationToken);
    }


    private static async ValueTask<KeyAttestationVerificationResult> VerifyCoreAsync(
        string compactAttestation,
        string? expectedNonce,
        bool nonceRequired,
        VerificationDelegate? verificationDelegate,
        Func<string, bool> isAttestationSigningAlgAcceptable,
        Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate? resolveWalletProviderKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan clockSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(isAttestationSigningAlgAcceptable);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        //Appendix D.1: a verifiable attestation MUST be a signed three-part JWS. The structural parser
        //also accepts the unsigned two-part form, which cannot be verified.
        if(string.IsNullOrEmpty(compactAttestation) || compactAttestation.Split('.').Length != 3)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.NotSigned);
        }

        //Body parse + typ/attested_keys validation reuses the structural parser (the serialization
        //firewall scan). A failure here is a malformed or mistyped attestation.
        if(!KeyAttestationParser.TryParse(compactAttestation, base64UrlDecoder, memoryPool, out KeyAttestation? attestation)
            || attestation is null)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.Malformed);
        }

        string? alg;
        bool hasJwk;
        bool hasKid;
        bool hasX5c;
        string? kid;
        List<string>? x5cValues;
        Dictionary<string, object>? jwkMembers;
        try
        {
            string[] segments = compactAttestation.Split('.');
            using IMemoryOwner<byte> headerOwner = base64UrlDecoder(segments[0], memoryPool);
            ReadOnlySpan<byte> header = headerOwner.Memory.Span;

            alg = JwkJsonReader.ExtractStringValue(header, WellKnownJwkMemberNames.AlgUtf8);
            hasJwk = JwkJsonReader.ContainsKey(header, WellKnownJoseHeaderNames.JwkUtf8);
            hasKid = JwkJsonReader.ContainsKey(header, KidHeaderUtf8);
            hasX5c = JwkJsonReader.ContainsKey(header, X5cHeaderUtf8);
            kid = hasKid ? JwkJsonReader.ExtractStringValue(header, KidHeaderUtf8) : null;
            x5cValues = hasX5c ? JwkJsonReader.ExtractStringArrayProperty(header, X5cHeaderUtf8) : null;
            jwkMembers = hasJwk
                ? JwkJsonReader.ExtractObjectProperties(header, WellKnownJoseHeaderNames.JwkUtf8)
                : null;
        }
        catch
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.Malformed);
        }

        //The attestation MUST be signed with a registered asymmetric signature algorithm the
        //application accepts; none/MAC are rejected.
        if(string.IsNullOrEmpty(alg)
            || WellKnownJwaValues.IsNone(alg)
            || !Oid4VciHeaderKeyResolution.IsAsymmetricSignatureAlg(alg)
            || !isAttestationSigningAlgAcceptable(alg))
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.InvalidAlg);
        }

        //Resolve the Wallet-Provider key the header references through the shared §F.1 machinery.
        Oid4VciHeaderKeyResolution.Outcome resolution = await Oid4VciHeaderKeyResolution.ResolveAsync(
            hasJwk,
            hasKid,
            hasX5c,
            jwkMembers,
            kid,
            x5cValues,
            alg,
            resolveWalletProviderKey,
            x509Verification,
            context,
            base64UrlDecoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        if(resolution.Status != HeaderKeyResolutionStatus.Resolved)
        {
            return KeyAttestationVerificationResult.Failure(MapResolutionFailure(resolution.Status));
        }

        PublicKeyMemory walletProviderKey = resolution.Key!;

        //Appendix D.1: "the signature on the attestation verifies". Composes Jws.VerifyAsync — the
        //registry overload resolves the verifier from the key's algorithm, the explicit overload uses
        //the supplied delegate.
        bool isSignatureValid;
        try
        {
            isSignatureValid = verificationDelegate is null
                ? await Jws.VerifyAsync(
                    compactAttestation,
                    base64UrlDecoder,
                    memoryPool,
                    walletProviderKey,
                    cancellationToken).ConfigureAwait(false)
                : await Jws.VerifyAsync(
                    compactAttestation,
                    base64UrlDecoder,
                    memoryPool,
                    walletProviderKey,
                    verificationDelegate,
                    cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            walletProviderKey.Dispose();
        }

        if(!isSignatureValid)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.SignatureFailed);
        }

        //Appendix D.1: a present exp bounds the attestation (and its attested keys); a past exp, with
        //the caller's skew leniency, expires it.
        if(attestation.ExpiresAt is DateTimeOffset expiresAt
            && expiresAt + clockSkew < timeProvider.GetUtcNow())
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.Expired);
        }

        //Appendix D.1: when the Issuer supplied a nonce, the attestation MUST echo it.
        if(nonceRequired)
        {
            if(attestation.Nonce is null)
            {
                return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.NonceMissing);
            }

            if(expectedNonce is null || !string.Equals(attestation.Nonce, expectedNonce, StringComparison.Ordinal))
            {
                return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.NonceMismatch);
            }
        }
        else if(attestation.Nonce is not null
            && expectedNonce is not null
            && !string.Equals(attestation.Nonce, expectedNonce, StringComparison.Ordinal))
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.NonceMismatch);
        }

        return KeyAttestationVerificationResult.Success(attestation);
    }


    //Adapts the public Wallet-Provider key resolver to the shared resolver's neutral kid-delegate type.
    //The two share a signature; this is a delegate-to-delegate retarget, not a captured-data closure.
    private static Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate? Adapt(ResolveWalletProviderKeyDelegate? resolve) =>
        resolve is null ? null : new Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate(resolve.Invoke);


    //Maps the shared header-key resolver's neutral status to the attestation verification failure reason.
    private static KeyAttestationVerificationFailureReason MapResolutionFailure(HeaderKeyResolutionStatus status) =>
        status switch
        {
            HeaderKeyResolutionStatus.KeyReferenceUnresolved => KeyAttestationVerificationFailureReason.KeyReferenceUnresolved,
            _ => KeyAttestationVerificationFailureReason.InvalidKeyReference
        };
}
