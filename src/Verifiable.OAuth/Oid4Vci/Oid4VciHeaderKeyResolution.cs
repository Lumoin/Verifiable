using System.Buffers;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Resolves the public key an OID4VCI JWS references through its JOSE header — the mutually-exclusive
/// <c>jwk</c> / <c>x5c</c> / <c>kid</c> trio of
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1">Appendix F.1</see>
/// — shared by the <c>jwt</c> key-proof validator (<see cref="CredentialProofValidator"/>) and the
/// key-attestation verifier (<see cref="KeyAttestationVerifier"/>) so the two cannot drift apart.
/// </summary>
/// <remarks>
/// The <c>jwk</c> mode is self-contained (the key travels in the header); <c>x5c</c> is resolved by the
/// library composing the existing X.509 surface against the context's trust anchors; <c>kid</c> is
/// dereferenced by a deployment-supplied delegate, whose DID-document / key-store trust is the
/// application's. The resolver reconstructs the key but never decides trust policy.
/// </remarks>
internal static class Oid4VciHeaderKeyResolution
{
    /// <summary>
    /// Resolves the key a <c>kid</c> JOSE header names. The deployment owns the trust the reference
    /// dereferences against; <paramref name="context"/> is threaded so a network-resolving <c>kid</c>
    /// (a <c>did:web</c> DID URL) is fetched under the context's SSRF policy. Returning
    /// <see langword="null"/> means the key could not be resolved.
    /// </summary>
    /// <param name="kid">The <c>kid</c> JOSE header value to dereference.</param>
    /// <param name="algorithm">The JWS <c>alg</c> header value.</param>
    /// <param name="context">The per-request context threaded for the SSRF policy.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The reconstructed public key, or <see langword="null"/> when unresolved.</returns>
    public delegate ValueTask<PublicKeyMemory?> ResolveKidKeyDelegate(
        string kid,
        string algorithm,
        ExchangeContext context,
        CancellationToken cancellationToken);


    /// <summary>The outcome of resolving the header key reference: the key on success, otherwise the reason.</summary>
    public readonly struct Outcome
    {
        private Outcome(PublicKeyMemory? key, HeaderKeyResolutionStatus status)
        {
            Key = key;
            Status = status;
        }


        /// <summary>The reconstructed public key when <see cref="Status"/> is <see cref="HeaderKeyResolutionStatus.Resolved"/>; otherwise <see langword="null"/>. The caller owns and disposes it.</summary>
        public PublicKeyMemory? Key { get; }

        /// <summary>Why resolution succeeded or failed.</summary>
        public HeaderKeyResolutionStatus Status { get; }

        /// <summary>Builds a resolved outcome carrying the key.</summary>
        public static Outcome Resolved(PublicKeyMemory key) => new(key, HeaderKeyResolutionStatus.Resolved);

        /// <summary>Builds a failed outcome carrying no key.</summary>
        public static Outcome Failed(HeaderKeyResolutionStatus status) => new(null, status);
    }


    /// <summary>
    /// Resolves the §F.1 header key reference from the already-extracted header pieces, enforcing the
    /// mutual exclusivity (exactly one of <c>jwk</c>/<c>kid</c>/<c>x5c</c>), rejecting a <c>jwk</c> that
    /// carries private/symmetric material, and dispatching to the matching reference mode. Never throws
    /// on untrusted header content — a malformed reference is a typed <see cref="Outcome"/>.
    /// </summary>
    /// <param name="hasJwk">Whether the header carries a <c>jwk</c>.</param>
    /// <param name="hasKid">Whether the header carries a <c>kid</c>.</param>
    /// <param name="hasX5c">Whether the header carries an <c>x5c</c>.</param>
    /// <param name="jwkMembers">The parsed <c>jwk</c> members when <paramref name="hasJwk"/>; otherwise <see langword="null"/>.</param>
    /// <param name="kid">The <c>kid</c> value when <paramref name="hasKid"/>; otherwise <see langword="null"/>.</param>
    /// <param name="x5cValues">The <c>x5c</c> certificate values when <paramref name="hasX5c"/>; otherwise <see langword="null"/>.</param>
    /// <param name="algorithm">The JWS <c>alg</c> header value, threaded to the <c>kid</c> resolver.</param>
    /// <param name="resolveKid">Resolves the <c>kid</c> reference mode, or <see langword="null"/> when that mode is unsupported.</param>
    /// <param name="x509Verification">Resolves the <c>x5c</c> reference mode, or <see langword="null"/> when that mode is unsupported.</param>
    /// <param name="context">The per-request context carrying the <c>x5c</c> trust anchors / validity instant and the SSRF policy.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the <c>jwk</c> coordinates.</param>
    /// <param name="memoryPool">Memory pool for the reconstructed key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The resolved key, or the reason it could not be resolved.</returns>
    public static async ValueTask<Outcome> ResolveAsync(
        bool hasJwk,
        bool hasKid,
        bool hasX5c,
        Dictionary<string, object>? jwkMembers,
        string? kid,
        List<string>? x5cValues,
        string algorithm,
        ResolveKidKeyDelegate? resolveKid,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        //§F.1: kid/jwk/x5c are mutually exclusive — exactly one MUST identify the key.
        int referenceCount = (hasJwk ? 1 : 0) + (hasKid ? 1 : 0) + (hasX5c ? 1 : 0);
        if(referenceCount != 1)
        {
            return Outcome.Failed(HeaderKeyResolutionStatus.InvalidKeyReference);
        }

        if(hasJwk)
        {
            if(jwkMembers is null)
            {
                return Outcome.Failed(HeaderKeyResolutionStatus.InvalidKeyReference);
            }

            //§F.4: "the header parameter does not contain a private key". Reject private/symmetric
            //jwk material BEFORE reconstructing the key.
            if(WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(jwkMembers.Keys))
            {
                return Outcome.Failed(HeaderKeyResolutionStatus.JwkContainsPrivateKey);
            }

            try
            {
                return Outcome.Resolved(ReconstructKeyFromJwk(jwkMembers, base64UrlDecoder, memoryPool));
            }
            catch
            {
                return Outcome.Failed(HeaderKeyResolutionStatus.InvalidKeyReference);
            }
        }

        if(hasX5c)
        {
            //§F.1: the first x5c certificate contains the key the JWS is bound to. Resolve the leaf key
            //through the existing X.509 surface, validated to the context's trust anchors.
            if(x509Verification is null || x5cValues is null || x5cValues.Count == 0)
            {
                return Outcome.Failed(HeaderKeyResolutionStatus.KeyReferenceUnresolved);
            }

            PublicKeyMemory? x5cKey = await ResolveKeyFromX5cAsync(x5cValues, x509Verification, context, cancellationToken)
                .ConfigureAwait(false);

            return x5cKey is null
                ? Outcome.Failed(HeaderKeyResolutionStatus.KeyReferenceUnresolved)
                : Outcome.Resolved(x5cKey);
        }

        if(resolveKid is not null && !string.IsNullOrEmpty(kid))
        {
            //§F.1: a kid names a key the deployment dereferences (typically a DID URL). Context is
            //threaded so a network-resolving kid is fetched under the context's SSRF policy.
            PublicKeyMemory? kidKey = await resolveKid(kid, algorithm, context, cancellationToken).ConfigureAwait(false);

            return kidKey is null
                ? Outcome.Failed(HeaderKeyResolutionStatus.KeyReferenceUnresolved)
                : Outcome.Resolved(kidKey);
        }

        //A kid/x5c reference whose seam is unwired (or a kid with no value) cannot be resolved.
        return Outcome.Failed(HeaderKeyResolutionStatus.KeyReferenceUnresolved);
    }


    /// <summary>
    /// Whether <paramref name="alg"/> is a registered asymmetric digital signature algorithm — the
    /// IANA JOSE signature registry minus <c>none</c> and the symmetric MACs (ECDSA, RSA PKCS#1,
    /// RSA-PSS, EdDSA). Whether a given alg is ALSO acceptable per issuer policy is the caller's.
    /// </summary>
    /// <param name="alg">The JWS <c>alg</c> header value.</param>
    /// <returns><see langword="true"/> when the algorithm is an asymmetric signature algorithm.</returns>
    public static bool IsAsymmetricSignatureAlg(string alg) =>
        WellKnownJwaValues.IsEcdsa(alg)
        || WellKnownJwaValues.IsRs256(alg)
        || WellKnownJwaValues.IsRs384(alg)
        || WellKnownJwaValues.IsRs512(alg)
        || WellKnownJwaValues.IsPs256(alg)
        || WellKnownJwaValues.IsPs384(alg)
        || WellKnownJwaValues.IsPs512(alg)
        || WellKnownJwaValues.IsEdDsa(alg);


    //Reconstructs a PublicKeyMemory from the header's jwk members, composing the library's single
    //JWK→algorithm converter (the same path the proof/attestation minters project FROM).
    private static PublicKeyMemory ReconstructKeyFromJwk(
        Dictionary<string, object> jwkMembers,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwkMembers, memoryPool, base64UrlDecoder);

        Tag tag = Tag.Create(algorithm).With(purpose).With(scheme);

        return new PublicKeyMemory(keyMaterial, tag);
    }


    //Resolves the leaf PublicKeyMemory from the header's x5c chain, composing the existing X.509
    //surface: parse + chain-validate to the issuer-supplied trust anchors / validity instant on the
    //context. Returns null (→ KeyReferenceUnresolved) when the trust material is absent or the chain
    //does not validate, rather than throwing.
    private static async ValueTask<PublicKeyMemory?> ResolveKeyFromX5cAsync(
        List<string> x5cValues,
        Oid4VciProofX509Verification x509Verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<PkiCertificateMemory>? trustAnchors = context.X509TrustAnchors;
        DateTimeOffset? validationTime = context.ValidationTime;
        if(trustAnchors is null || validationTime is null)
        {
            return null;
        }

        IReadOnlyList<PkiCertificateMemory> chain;
        try
        {
            chain = x509Verification.ParseX5c(x5cValues, x509Verification.MemoryPool);
        }
        catch
        {
            return null;
        }

        try
        {
            return await x509Verification.ValidateChain(
                chain, trustAnchors, validationTime.Value, x509Verification.MemoryPool, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
        finally
        {
            foreach(PkiCertificateMemory cert in chain)
            {
                cert.Dispose();
            }
        }
    }
}
