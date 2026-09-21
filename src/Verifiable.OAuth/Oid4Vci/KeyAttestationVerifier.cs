using System.Buffers;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;

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
/// <see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, CancellationToken)"/>. The Wallet-Provider trust anchors remain the application's seam: the
/// <c>x5c</c> chain validates to <c>ExchangeContext.X509TrustAnchors</c> and the <c>kid</c> mode is
/// dereferenced by <see cref="Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate"/>.
/// </para>
/// <para>
/// Verification is fail-closed over untrusted input — a malformed attestation yields a
/// <see cref="KeyAttestationVerificationResult"/> carrying a
/// <see cref="KeyAttestationVerificationFailureReason"/>, never a thrown exception.
/// </para>
/// </remarks>
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
        BaseMemoryPool memoryPool,
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
        BaseMemoryPool memoryPool,
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
        BaseMemoryPool memoryPool,
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

            //RFC 7515 §4: gate the header for well-formedness — a repeated "alg"/"kid"/"jwk"/"x5c" at any
            //nesting depth — before extracting any of them, so the key-material selection below never
            //runs against a first occurrence while a duplicate second occurrence goes unnoticed.
            if(!JwkJsonReader.IsWellFormedJsonDocument(header))
            {
                return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.Malformed);
            }

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
            //The attestation header is client-supplied wire input, structurally unverified at this point;
            //any decode/read failure is a malformed attestation rather than an internal fault.
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
        using(walletProviderKey)
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


    /// <summary>
    /// Checks a verified attestation's <c>key_storage</c> and <c>user_authentication</c> assurance
    /// arrays against the Credential Issuer's own accepted-value constraints.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D.1">OID4VCI
    /// 1.0 Appendix D.1</see> defines the two constraints as "OPTIONAL. A non-empty array of case
    /// sensitive strings that assert the attack potential resistance of the key storage component" (and,
    /// for <c>user_authentication</c>, "of the user authentication methods allowed to access the private
    /// keys") "attested in the <c>attested_keys</c> parameter".
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">§12.2.4</see>
    /// states the metadata-side mirror of that same array as "a non-empty array... accepted by the
    /// Credential Issuer" — a constraint is therefore a MEMBERSHIP SET: the check is satisfied when at
    /// least one attested value is a member of the accepted set, never an ordering between values, and
    /// an absent or empty constraint constrains nothing.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-D.2">Appendix
    /// D.2</see> defines four ISO 18045 attack-potential values (<c>iso_18045_high</c>,
    /// <c>iso_18045_moderate</c>, <c>iso_18045_enhanced-basic</c>, <c>iso_18045_basic</c>) and states
    /// "ecosystems may define their own values" — a non-ISO value is "RECOMMENDED" to be a URL, compared
    /// the same way, by ordinal string equality.
    /// </summary>
    /// <param name="attestation">The already-verified attestation whose <c>KeyStorageJson</c> and <c>UserAuthenticationJson</c> arrays are checked.</param>
    /// <param name="acceptedKeyStorageValues">The Credential Issuer's <c>key_storage</c> accepted-value set, or <see langword="null"/>/empty when unconstrained.</param>
    /// <param name="acceptedUserAuthenticationValues">The Credential Issuer's <c>user_authentication</c> accepted-value set, or <see langword="null"/>/empty when unconstrained.</param>
    /// <param name="pool">Memory pool for the scratch buffer the attested arrays are read through.</param>
    /// <returns>
    /// A result whose <see cref="KeyAttestationVerificationResult.IsValid"/> is <see langword="true"/>
    /// when both constraints are satisfied (or unconstrained), or a failure naming
    /// <see cref="KeyAttestationVerificationFailureReason.KeyStorageConstraintUnsatisfied"/>,
    /// <see cref="KeyAttestationVerificationFailureReason.UserAuthenticationConstraintUnsatisfied"/>, or
    /// <see cref="KeyAttestationVerificationFailureReason.AssuranceConstraintValuesMalformed"/>.
    /// </returns>
    public static KeyAttestationVerificationResult CheckAssuranceConstraints(
        KeyAttestation attestation,
        IReadOnlyCollection<string>? acceptedKeyStorageValues,
        IReadOnlyCollection<string>? acceptedUserAuthenticationValues,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNull(pool);

        AssuranceConstraintOutcome keyStorageOutcome = CheckAssuranceConstraint(attestation.KeyStorageJson, acceptedKeyStorageValues, pool);
        if(keyStorageOutcome == AssuranceConstraintOutcome.Malformed)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.AssuranceConstraintValuesMalformed);
        }

        if(keyStorageOutcome == AssuranceConstraintOutcome.Unsatisfied)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.KeyStorageConstraintUnsatisfied);
        }

        AssuranceConstraintOutcome userAuthenticationOutcome = CheckAssuranceConstraint(attestation.UserAuthenticationJson, acceptedUserAuthenticationValues, pool);
        if(userAuthenticationOutcome == AssuranceConstraintOutcome.Malformed)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.AssuranceConstraintValuesMalformed);
        }

        if(userAuthenticationOutcome == AssuranceConstraintOutcome.Unsatisfied)
        {
            return KeyAttestationVerificationResult.Failure(KeyAttestationVerificationFailureReason.UserAuthenticationConstraintUnsatisfied);
        }

        return KeyAttestationVerificationResult.Success(attestation);
    }


    /// <summary>
    /// The three-way outcome one assurance array's membership check can reach, folded into the caller's
    /// closed <see cref="KeyAttestationVerificationFailureReason"/> vocabulary at the call site.
    /// </summary>
    private enum AssuranceConstraintOutcome
    {
        /// <summary>An unconstrained check, or a constraint at least one attested value is a member of.</summary>
        Satisfied,

        /// <summary>A non-empty constraint no attested value is a member of.</summary>
        Unsatisfied,

        /// <summary>A constrained attestation array that does not read as a JSON array of strings.</summary>
        Malformed
    }


    /// <summary>
    /// An absent or empty constraint constrains nothing (Appendix D.1's "non-empty array... accepted by
    /// the Credential Issuer" — an empty or missing array is not a constraint). A present, non-empty
    /// constraint is satisfied by ordinal-equality membership (Appendix D.2 sets no order between
    /// values); a constrained attestation array that does not read as a JSON array of strings answers
    /// <see cref="AssuranceConstraintOutcome.Malformed"/> rather than a silent
    /// <see cref="AssuranceConstraintOutcome.Unsatisfied"/>, since the membership question could not be
    /// asked at all.
    /// </summary>
    /// <param name="attestedArrayJson">The attestation's verbatim <c>key_storage</c> or <c>user_authentication</c> array text, or <see langword="null"/> when absent.</param>
    /// <param name="acceptedValues">The Credential Issuer's accepted-value set for this array, or <see langword="null"/>/empty when unconstrained.</param>
    /// <param name="pool">Memory pool for the scratch buffer the attested array is read through.</param>
    /// <returns>The membership outcome for this one array.</returns>
    private static AssuranceConstraintOutcome CheckAssuranceConstraint(string? attestedArrayJson, IReadOnlyCollection<string>? acceptedValues, BaseMemoryPool pool)
    {
        if(acceptedValues is null || acceptedValues.Count == 0)
        {
            return AssuranceConstraintOutcome.Satisfied;
        }

        List<string>? attestedValues = ExtractStringArrayElements(attestedArrayJson, pool);
        if(attestedValues is null)
        {
            return AssuranceConstraintOutcome.Malformed;
        }

        HashSet<string> acceptedSet = new(acceptedValues, StringComparer.Ordinal);
        foreach(string attestedValue in attestedValues)
        {
            if(acceptedSet.Contains(attestedValue))
            {
                return AssuranceConstraintOutcome.Satisfied;
            }
        }

        return AssuranceConstraintOutcome.Unsatisfied;
    }


    /// <summary>The synthetic single-property key <see cref="ExtractStringArrayElements"/> wraps a bare attested array under.</summary>
    private static ReadOnlySpan<byte> AssuranceArrayWrapperKeyUtf8 => "v"u8;

    /// <summary>The bytes that open the one-property wrapper object, up to and including the colon after its key.</summary>
    private static ReadOnlySpan<byte> AssuranceArrayWrapperPrefixUtf8 => "{\"v\":"u8;

    /// <summary>The byte that closes the one-property wrapper object.</summary>
    private static ReadOnlySpan<byte> AssuranceArrayWrapperSuffixUtf8 => "}"u8;


    /// <summary>
    /// Reads every string element of a verbatim attested assurance array. <see cref="KeyAttestation.KeyStorageJson"/>
    /// and <see cref="KeyAttestation.UserAuthenticationJson"/> hold the BARE JSON array text (e.g.
    /// <c>["iso_18045_moderate"]</c>), never an object, while
    /// <see cref="JwkJsonReader.ExtractStringArrayProperty"/> walks exactly this shape but
    /// locates its array by an object property key. The bare array is therefore wrapped in a
    /// one-property object under <see cref="AssuranceArrayWrapperKeyUtf8"/> before that existing,
    /// unmodified reader walks it — reusing the shipped span-based array-of-strings walker rather than
    /// writing a second one. The wrapper is composed in a buffer rented from <paramref name="pool"/>.
    /// </summary>
    /// <param name="arrayJson">The verbatim bare JSON array text, or <see langword="null"/>/empty when absent.</param>
    /// <param name="pool">Memory pool the wrapper buffer is rented from.</param>
    /// <returns>The decoded string elements in array order, or <see langword="null"/> when absent or not a well-formed string array.</returns>
    private static List<string>? ExtractStringArrayElements(string? arrayJson, BaseMemoryPool pool)
    {
        if(string.IsNullOrEmpty(arrayJson))
        {
            return null;
        }

        ReadOnlySpan<byte> prefix = AssuranceArrayWrapperPrefixUtf8;
        ReadOnlySpan<byte> suffix = AssuranceArrayWrapperSuffixUtf8;
        int arrayByteCount = Encoding.UTF8.GetByteCount(arrayJson);
        int wrappedLength = prefix.Length + arrayByteCount + suffix.Length;

        using IMemoryOwner<byte> wrappedOwner = pool.Rent(wrappedLength);
        Span<byte> wrapped = wrappedOwner.Memory.Span[..wrappedLength];
        prefix.CopyTo(wrapped);
        _ = Encoding.UTF8.GetBytes(arrayJson, wrapped[prefix.Length..]);
        suffix.CopyTo(wrapped[(prefix.Length + arrayByteCount)..]);

        return JwkJsonReader.ExtractStringArrayProperty(wrapped, AssuranceArrayWrapperKeyUtf8);
    }


    /// <summary>
    /// Adapts the public Wallet-Provider key resolver to the shared resolver's neutral kid-delegate
    /// type. The two share a signature; this is a delegate-to-delegate retarget, not a captured-data
    /// closure.
    /// </summary>
    /// <param name="resolve">The public delegate to adapt, or <see langword="null"/> when the <c>kid</c> mode is unsupported.</param>
    /// <returns>The adapted delegate, or <see langword="null"/> when <paramref name="resolve"/> is <see langword="null"/>.</returns>
    private static Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate? Adapt(ResolveWalletProviderKeyDelegate? resolve) =>
        resolve is null ? null : new Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate(resolve.Invoke);


    /// <summary>Maps the shared header-key resolver's neutral status to the attestation verification failure reason.</summary>
    /// <param name="status">The shared resolver's outcome status.</param>
    /// <returns>The corresponding <see cref="KeyAttestationVerificationFailureReason"/>.</returns>
    private static KeyAttestationVerificationFailureReason MapResolutionFailure(HeaderKeyResolutionStatus status) =>
        status switch
        {
            HeaderKeyResolutionStatus.KeyReferenceUnresolved => KeyAttestationVerificationFailureReason.KeyReferenceUnresolved,

            //HeaderKeyResolutionStatus has no attestation-specific counterpart for a jwk carrying
            //private key material; it is an invalid key reference here too.
            HeaderKeyResolutionStatus.JwkContainsPrivateKey => KeyAttestationVerificationFailureReason.InvalidKeyReference,
            HeaderKeyResolutionStatus.InvalidKeyReference => KeyAttestationVerificationFailureReason.InvalidKeyReference,
            HeaderKeyResolutionStatus.Resolved => KeyAttestationVerificationFailureReason.InvalidKeyReference,

            _ => KeyAttestationVerificationFailureReason.InvalidKeyReference
        };
}
