using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Validates an OID4VCI 1.0 <c>jwt</c> key proof (the <c>openid4vci-proof+jwt</c> proof type of
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1">Appendix F.1</see>),
/// performing the Credential Issuer's proof-validation checks of
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.4">Appendix F.4</see>.
/// This is the symmetric counterpart to <see cref="Wallet.Oid4VciProofIssuance.BuildJwtProofAsync"/>
/// — a proof that minter produces round-trips through this validator.
/// </summary>
/// <remarks>
/// <para>
/// The validator composes the library's existing primitives rather than re-rolling crypto:
/// the header and claims are scanned with <see cref="JwkJsonReader"/> (the <c>Verifiable.OAuth</c>
/// serialization firewall), the holder key is reconstructed with
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>, the signature is checked
/// with <see cref="Jws.VerifyAsync"/>, the RFC 7638 thumbprint is computed with
/// <see cref="DpopJwkUtilities.ComputeThumbprintFromJwk"/>, and the <c>iat</c> window is the shared
/// <see cref="JwtTemporalChecks"/> arithmetic.
/// </para>
/// <para>
/// The <c>c_nonce</c> the proof must echo is supplied by the caller as
/// <see cref="CredentialProofValidationRequest.ExpectedNonce"/>; the Credential Issuer's
/// <c>c_nonce</c> store and its single-use retirement remain the application's responsibility.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialProofValidator")]
public static class CredentialProofValidator
{
    //The §F.1 OPTIONAL key-reference JOSE headers whose mutual exclusivity §F.1 mandates. Only
    //their PRESENCE is detected here (for the exactly-one rule); dereferencing kid/x5c is the
    //deployment's job via the key-resolution delegate.
    private static ReadOnlySpan<byte> KidHeaderUtf8 => "kid"u8;
    private static ReadOnlySpan<byte> X5cHeaderUtf8 => "x5c"u8;

    /// <summary>
    /// Resolves the holder public key a <c>jwt</c> proof references through its <c>kid</c> JOSE
    /// header — the §F.1 reference mode that names a key the issuer dereferences (typically a DID
    /// URL into a DID Document, but it may equally be an issuer-side key-store identifier). The
    /// deployment owns the DID-document / key-store trust the reference dereferences against, so the
    /// resolution is an application seam; the <c>x5c</c> mode is resolved by the library itself via
    /// <see cref="Oid4VciProofX509Verification"/> (it composes the existing X.509 surface).
    /// Returning <see langword="null"/> means the key could not be resolved and the proof is
    /// rejected.
    /// </summary>
    /// <remarks>
    /// The <paramref name="context"/> is threaded so a <c>kid</c> the deployment resolves over the
    /// network (a <c>did:web</c> DID URL) is fetched under the context's SSRF
    /// <c>OutboundFetchPolicy</c> — exactly as the <c>di_vp</c> path threads the same context into
    /// <see cref="DidResolver.ResolveAsync"/>.
    /// </remarks>
    /// <param name="kid">The proof's <c>kid</c> JOSE header value — the key identifier to dereference.</param>
    /// <param name="algorithm">The proof's <c>alg</c> header value.</param>
    /// <param name="context">The per-request context threaded to a network-resolving <c>kid</c> for its SSRF policy.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The reconstructed holder public key, or <see langword="null"/> when unresolved.</returns>
    public delegate ValueTask<PublicKeyMemory?> ResolveProofKeyDelegate(
        string kid,
        string algorithm,
        ExchangeContext context,
        CancellationToken cancellationToken);


    /// <summary>
    /// Validates one <c>jwt</c> key proof against the Credential Issuer's §F.4 checks using an
    /// explicit <paramref name="verificationDelegate"/> for the signature step.
    /// </summary>
    /// <param name="request">The proof plus the expected audience and nonce.</param>
    /// <param name="verificationDelegate">The signature-verification function for the proof's algorithm.</param>
    /// <param name="isProofSigningAlgAcceptable">Predicate deciding whether the proof's <c>alg</c> is acceptable per the issuer's <c>proof_signing_alg_values_supported</c> / local policy.</param>
    /// <param name="resolveProofKey">Resolves the key for the <c>kid</c> reference mode, or <see langword="null"/> when that mode is not supported.</param>
    /// <param name="x509Verification">Resolves the key for the <c>x5c</c> reference mode by composing the existing X.509 surface, or <see langword="null"/> when that mode is not supported.</param>
    /// <param name="context">The per-request context threaded to a network-resolving <c>kid</c> and carrying the <c>x5c</c> trust anchors / validation time.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for the thumbprint.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the JWS segments and JWK coordinates.</param>
    /// <param name="timeProvider">The clock the <c>iat</c> window is measured against.</param>
    /// <param name="memoryPool">Memory pool for the transient decode/verify buffers.</param>
    /// <param name="iatSkew">The half-width of the <c>iat</c> acceptance window (§13.8).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The per-check verdict carrying the bound key thumbprint on success.</returns>
    public static async ValueTask<CredentialProofValidationResult> ValidateAsync(
        CredentialProofValidationRequest request,
        VerificationDelegate verificationDelegate,
        Func<string, bool> isProofSigningAlgAcceptable,
        ResolveProofKeyDelegate? resolveProofKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(isProofSigningAlgAcceptable);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        return await ValidateCoreAsync(
            request,
            verificationDelegate,
            isProofSigningAlgAcceptable,
            resolveProofKey,
            x509Verification,
            context,
            base64UrlEncoder,
            base64UrlDecoder,
            timeProvider,
            memoryPool,
            iatSkew,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates one <c>jwt</c> key proof against the Credential Issuer's §F.4 checks, resolving
    /// the signature-verification function from the registered cryptographic backends keyed on the
    /// reconstructed holder key's algorithm. Delegates to the explicit-delegate overload once the
    /// key is reconstructed.
    /// </summary>
    public static async ValueTask<CredentialProofValidationResult> ValidateAsync(
        CredentialProofValidationRequest request,
        Func<string, bool> isProofSigningAlgAcceptable,
        ResolveProofKeyDelegate? resolveProofKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(isProofSigningAlgAcceptable);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);

        return await ValidateCoreAsync(
            request,
            verificationDelegate: null,
            isProofSigningAlgAcceptable,
            resolveProofKey,
            x509Verification,
            context,
            base64UrlEncoder,
            base64UrlDecoder,
            timeProvider,
            memoryPool,
            iatSkew,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates each entry of a §8.2 <c>proofs</c> batch under the same §F.4 checks, resolving the
    /// signature-verification function from the registered backends. The result is the per-entry
    /// list in request order; a caller treats any non-<see cref="CredentialProofValidationResult.IsValid"/>
    /// entry as the §8.3.1.2 error its <see cref="CredentialProofValidationResult.FailureReason"/> maps to.
    /// </summary>
    /// <param name="proofs">The compact <c>jwt</c> proofs from the §8.2 <c>proofs.jwt</c> array.</param>
    public static async ValueTask<IReadOnlyList<CredentialProofValidationResult>> ValidateBatchAsync(
        IReadOnlyList<string> proofs,
        string expectedAudience,
        string? expectedNonce,
        bool nonceRequired,
        Func<string, bool> isProofSigningAlgAcceptable,
        ResolveProofKeyDelegate? resolveProofKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proofs);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);
        ArgumentNullException.ThrowIfNull(context);

        List<CredentialProofValidationResult> results = new(proofs.Count);
        foreach(string proof in proofs)
        {
            CredentialProofValidationResult result = await ValidateAsync(
                new CredentialProofValidationRequest
                {
                    Proof = proof,
                    ExpectedAudience = expectedAudience,
                    ExpectedNonce = expectedNonce,
                    NonceRequired = nonceRequired
                },
                isProofSigningAlgAcceptable,
                resolveProofKey,
                x509Verification,
                context,
                base64UrlEncoder,
                base64UrlDecoder,
                timeProvider,
                memoryPool,
                iatSkew,
                cancellationToken).ConfigureAwait(false);

            results.Add(result);
        }

        return results;
    }


    /// <summary>
    /// Validates one OID4VCI 1.0 Appendix F.2 <c>di_vp</c> key proof — a W3C Verifiable Presentation
    /// secured with a Data Integrity proof — by COMPOSING the library's tested
    /// <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/> surface (W3C VC Data Integrity
    /// §4.3 Verify Proof). It deserializes the presentation, resolves the holder DID document through
    /// the supplied <see cref="DiVpProofVerification.Resolver"/> (threading <paramref name="context"/>
    /// so a remote holder is fetched under its SSRF policy), and verifies the embedded proof with
    /// <paramref name="expectedChallenge"/> mapped to the server-provided <c>c_nonce</c> and
    /// <paramref name="expectedDomain"/> mapped to the Credential Issuer Identifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Appendix F.2 fixes the <c>di_vp</c> binding: a presentation proof's "proofPurpose: REQUIRED.
    /// MUST be set to authentication", its "domain: REQUIRED. MUST be set to the Credential Issuer
    /// Identifier", and its "challenge ... where the value is a server-provided c_nonce". The
    /// underlying verifier already enforces every one of these — the <c>authentication</c> proof
    /// purpose, the <c>challenge</c> equality, the <c>domain</c> set-equality, and the key resolution
    /// through the holder's <c>authentication</c> relationship — so this method is the spec mapping,
    /// not new cryptographic logic. Appendix F.2 also requires the Credential Issuer to "validate
    /// that the W3C Verifiable Presentation used as a proof is actually signed with a key in the
    /// possession of the Holder"; that is exactly the holder-key signature check the composed
    /// verifier performs.
    /// </para>
    /// <para>
    /// The result maps a <see cref="VerificationFailureReason.ChallengeMismatch"/> to
    /// <see cref="DiVpProofValidationFailureReason.ChallengeMismatch"/> (the §8.3.1.2
    /// <c>invalid_nonce</c> case, since the <c>challenge</c> IS the <c>c_nonce</c>); every other
    /// Data Integrity failure maps to a reason the endpoint answers as <c>invalid_proof</c>. On
    /// success it carries the authenticated holder verification method id — the binding the issued
    /// Credential uses.
    /// </para>
    /// </remarks>
    /// <param name="presentationJson">One <c>di_vp</c> array entry's serialized JSON.</param>
    /// <param name="expectedChallenge">The server-provided <c>c_nonce</c> the proof's <c>challenge</c> must equal.</param>
    /// <param name="expectedDomain">The Credential Issuer Identifier the proof's <c>domain</c> must equal.</param>
    /// <param name="verification">The application-supplied deserialize / DID-resolver / Data Integrity seams.</param>
    /// <param name="context">The per-request context bag threaded to <see cref="DidResolver.ResolveAsync"/> and the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verdict carrying the authenticated holder verification method id on success.</returns>
    public static async ValueTask<DiVpProofValidationResult> ValidateDiVpAsync(
        string presentationJson,
        string expectedChallenge,
        string expectedDomain,
        DiVpProofVerification verification,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(presentationJson);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedChallenge);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedDomain);
        ArgumentNullException.ThrowIfNull(verification);
        ArgumentNullException.ThrowIfNull(context);

        DataIntegritySecuredPresentation? presentation = verification.Deserialize(presentationJson);
        if(presentation is null)
        {
            return DiVpProofValidationResult.Failure(DiVpProofValidationFailureReason.Unparseable);
        }

        //Appendix F.2 binds the presentation to the Holder: the presentation's holder member states
        //the DID, and its proof's verificationMethod names the key under that DID. The holder DID is
        //the holder member when present, else the base DID of the proof's verificationMethod DID URL.
        string? holderDid = DeriveHolderDid(presentation);
        if(holderDid is null)
        {
            return DiVpProofValidationResult.Failure(DiVpProofValidationFailureReason.HolderUnresolved);
        }

        //Resolve the holder DID document through the library's DID-resolution seam, threading the
        //credential endpoint's context so a remote did:web holder is fetched under the context's
        //OutboundFetch SSRF policy. A non-document result (resolution failure, or a method that
        //yields a URL the caller must fetch but no document) cannot anchor the holder key.
        DidResolutionResult resolution = await verification.Resolver.ResolveAsync(
            holderDid, context, options: null, cancellationToken).ConfigureAwait(false);
        if(!resolution.IsSuccessful || resolution.Document is null)
        {
            return DiVpProofValidationResult.Failure(DiVpProofValidationFailureReason.HolderUnresolved);
        }

        CredentialVerificationResult<DataIntegritySecuredPresentation> result = await presentation.VerifyAsync(
            resolution.Document,
            expectedChallenge,
            expectedDomain,
            verification.Canonicalize,
            verification.ContextResolver,
            verification.DecodeProofValue,
            verification.SerializePresentation,
            verification.SerializeProofOptions,
            verification.Decoder,
            verification.ComputeDigest,
            verification.MemoryPool,
            context,
            cancellationToken).ConfigureAwait(false);

        if(result.IsValid && result.Verified is Verified<DataIntegritySecuredPresentation> verified)
        {
            //The composed verifier carries the authenticated verification method id as a KeyId on
            //the Verified value's provenance tag — the holder key the issued Credential binds to.
            string? verificationMethodId = verified.Context.TryGet<KeyId>(out KeyId keyId)
                ? keyId.Value
                : null;

            return DiVpProofValidationResult.Success(verificationMethodId ?? string.Empty);
        }

        return DiVpProofValidationResult.Failure(MapDiVpFailure(result.FailureReason));
    }


    //Appendix F.2: the holder DID is the presentation's holder member when present, else the base
    //DID of the proof's verificationMethod DID URL — the DID the verificationMethod key lives under.
    //Returns null when neither names a resolvable DID, which the caller treats as an unresolved
    //holder (invalid_proof).
    private static string? DeriveHolderDid(DataIntegritySecuredPresentation presentation)
    {
        if(!string.IsNullOrEmpty(presentation.Holder))
        {
            return presentation.Holder;
        }

        string? verificationMethodId = presentation.Proof?.Count > 0
            ? presentation.Proof[0].VerificationMethod?.Id
            : null;

        if(verificationMethodId is not null && DidUrl.TryParseAbsolute(verificationMethodId, out DidUrl? parsed))
        {
            return parsed.BaseDid;
        }

        return null;
    }


    //Maps the W3C Data Integrity presentation-verification failure to the closed di_vp reason set.
    //ChallengeMismatch stays distinct so the endpoint can answer §8.3.1.2 invalid_nonce; every
    //other Data Integrity failure is an invalid_proof condition.
    private static DiVpProofValidationFailureReason MapDiVpFailure(VerificationFailureReason reason) =>
        reason switch
        {
            VerificationFailureReason.NoProof => DiVpProofValidationFailureReason.NoProof,
            VerificationFailureReason.ProofPurposeMismatch => DiVpProofValidationFailureReason.ProofPurposeMismatch,
            VerificationFailureReason.ChallengeMismatch => DiVpProofValidationFailureReason.ChallengeMismatch,
            VerificationFailureReason.DomainMismatch => DiVpProofValidationFailureReason.DomainMismatch,
            VerificationFailureReason.VerificationMethodNotFound => DiVpProofValidationFailureReason.VerificationMethodNotFound,
            VerificationFailureReason.MissingVerificationMethod => DiVpProofValidationFailureReason.VerificationMethodNotFound,
            _ => DiVpProofValidationFailureReason.SignatureInvalid
        };


    //The single fail-closed validation path. A null verificationDelegate selects the
    //registry-resolved verifier keyed on the reconstructed holder key's algorithm.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The reconstructed/resolved PublicKeyMemory is disposed in the finally block of the verification try; the analyzer does not trace the assign-then-finally path across the reconstruction branches here.")]
    private static async ValueTask<CredentialProofValidationResult> ValidateCoreAsync(
        CredentialProofValidationRequest request,
        VerificationDelegate? verificationDelegate,
        Func<string, bool> isProofSigningAlgAcceptable,
        ResolveProofKeyDelegate? resolveProofKey,
        Oid4VciProofX509Verification? x509Verification,
        ExchangeContext context,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        CancellationToken cancellationToken)
    {
        //Structural parse first — reject obviously malformed input cheaply.
        string[] parts = request.Proof.Split('.');
        if(parts.Length != 3
            || string.IsNullOrEmpty(parts[0])
            || string.IsNullOrEmpty(parts[1])
            || string.IsNullOrEmpty(parts[2]))
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.Malformed);
        }

        string? typ;
        string? alg;
        bool hasJwk;
        bool hasKid;
        bool hasX5c;
        string? kid;
        List<string>? x5cValues;
        Dictionary<string, object>? jwkMembers;
        string? audience;
        bool hasIat;
        long iatSeconds;
        string? nonce;
        try
        {
            using IMemoryOwner<byte> headerOwner = base64UrlDecoder(parts[0], memoryPool);
            ReadOnlySpan<byte> header = headerOwner.Memory.Span;
            typ = JwkJsonReader.ExtractStringValue(header, WellKnownJoseHeaderNames.TypUtf8);
            alg = JwkJsonReader.ExtractStringValue(header, WellKnownJwkMemberNames.AlgUtf8);
            hasJwk = JwkJsonReader.ContainsKey(header, WellKnownJoseHeaderNames.JwkUtf8);
            hasKid = JwkJsonReader.ContainsKey(header, KidHeaderUtf8);
            hasX5c = JwkJsonReader.ContainsKey(header, X5cHeaderUtf8);
            kid = hasKid ? JwkJsonReader.ExtractStringValue(header, KidHeaderUtf8) : null;
            x5cValues = hasX5c ? JwkJsonReader.ExtractStringArrayProperty(header, X5cHeaderUtf8) : null;
            jwkMembers = hasJwk
                ? JwkJsonReader.ExtractObjectProperties(header, WellKnownJoseHeaderNames.JwkUtf8)
                : null;

            using IMemoryOwner<byte> payloadOwner = base64UrlDecoder(parts[1], memoryPool);
            ReadOnlySpan<byte> payload = payloadOwner.Memory.Span;
            audience = JwkJsonReader.ExtractStringValue(payload, WellKnownJwtClaimNames.AudUtf8);
            hasIat = JwkJsonReader.TryExtractLongValue(payload, WellKnownJwtClaimNames.IatUtf8, out iatSeconds);
            nonce = JwkJsonReader.ExtractStringValue(payload, WellKnownJwtClaimNames.NonceUtf8);
        }
        catch
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.Malformed);
        }

        //§F.4: "the key proof is explicitly typed using header parameters as defined for that
        //proof type" — §F.1 fixes that typing to typ = openid4vci-proof+jwt.
        if(!string.Equals(typ, Wallet.Oid4VciProofIssuance.ProofJwtType, StringComparison.Ordinal))
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.InvalidTyp);
        }

        //§F.1: "alg ... MUST NOT be none or an identifier for a symmetric algorithm (MAC)";
        //§F.4: "the header parameter indicates a registered asymmetric digital signature
        //algorithm, alg parameter value is not none, is supported by the application, and is
        //acceptable per local policy".
        if(string.IsNullOrEmpty(alg)
            || WellKnownJwaValues.IsNone(alg)
            || !Oid4VciHeaderKeyResolution.IsAsymmetricSignatureAlg(alg)
            || !isProofSigningAlgAcceptable(alg))
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.InvalidAlg);
        }

        //Reconstruct the holder public key. §F.4: "The Credential Issuer MUST validate that the JWT
        //used as a proof is actually signed by a key identified in the JOSE Header through either
        //kid, jwk or x5c element." The shared resolver enforces the §F.1 mutual exclusivity, rejects a
        //private/symmetric jwk, and dispatches to the matching reference mode (jwk self-contained, x5c
        //via the X.509 surface, kid via the deployment delegate); the validator owns the reconstructed
        //key and disposes it after the verify call.
        Oid4VciHeaderKeyResolution.Outcome resolution = await Oid4VciHeaderKeyResolution.ResolveAsync(
            hasJwk,
            hasKid,
            hasX5c,
            jwkMembers,
            kid,
            x5cValues,
            alg,
            resolveProofKey is null ? null : new Oid4VciHeaderKeyResolution.ResolveKidKeyDelegate(resolveProofKey.Invoke),
            x509Verification,
            context,
            base64UrlDecoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        if(resolution.Status != HeaderKeyResolutionStatus.Resolved)
        {
            return CredentialProofValidationResult.Failure(MapResolutionFailure(resolution.Status));
        }

        PublicKeyMemory publicKey = resolution.Key!;

        //§F.4: "the signature on the key proof verifies with the public key contained in the
        //header parameter". Composes Jws.VerifyAsync — the registry overload resolves the verifier
        //from the key's algorithm, the explicit overload uses the supplied delegate.
        bool isSignatureValid;
        try
        {
            isSignatureValid = verificationDelegate is null
                ? await Jws.VerifyAsync(
                    request.Proof,
                    base64UrlDecoder,
                    memoryPool,
                    publicKey,
                    cancellationToken).ConfigureAwait(false)
                : await Jws.VerifyAsync(
                    request.Proof,
                    base64UrlDecoder,
                    memoryPool,
                    publicKey,
                    verificationDelegate,
                    cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            publicKey.Dispose();
        }

        if(!isSignatureValid)
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.SignatureFailed);
        }

        //§F.1: "aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer
        //Identifier".
        if(audience is null || !string.Equals(audience, request.ExpectedAudience, StringComparison.Ordinal))
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.AudienceMismatch);
        }

        //§F.1: "iat: REQUIRED (number)"; §F.4: "the creation time of the JWT ... is within an
        //acceptable window". Reuses the shared temporal atoms — no re-rolled arithmetic.
        if(!hasIat)
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.IatOutOfWindow);
        }

        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatSeconds);
        DateTimeOffset now = timeProvider.GetUtcNow();
        if(!JwtTemporalChecks.IsNotStale(issuedAt, now, iatSkew)
            || !JwtTemporalChecks.IsNotInFuture(issuedAt, now, iatSkew))
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.IatOutOfWindow);
        }

        //§F.4: "if the server has a Nonce Endpoint, the nonce in the key proof matches the
        //server-provided c_nonce value". NonceRequired tracks that the issuer minted a c_nonce.
        if(request.NonceRequired)
        {
            if(nonce is null)
            {
                return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.NonceMissing);
            }

            if(request.ExpectedNonce is null
                || !string.Equals(nonce, request.ExpectedNonce, StringComparison.Ordinal))
            {
                return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.NonceMismatch);
            }
        }
        else if(nonce is not null
            && request.ExpectedNonce is not null
            && !string.Equals(nonce, request.ExpectedNonce, StringComparison.Ordinal))
        {
            return CredentialProofValidationResult.Failure(CredentialProofValidationFailureReason.NonceMismatch);
        }

        //The bound key the issued Credential binds to: the RFC 7638 thumbprint of the proof's key.
        //For the kid/x5c modes the resolver reconstructed the same key family, so the thumbprint is
        //computed off the embedded jwk only — those modes carry no jwk and yield no thumbprint here.
        string? thumbprint = hasJwk && jwkMembers is not null
            ? DpopJwkUtilities.ComputeThumbprintFromJwk(
                ToStringValuedJwk(jwkMembers), base64UrlEncoder, memoryPool)
            : null;

        return CredentialProofValidationResult.Success(thumbprint ?? string.Empty, audience, issuedAt, nonce);
    }


    //Maps the shared header-key resolver's neutral status to the §F.4 proof-validation failure reason.
    private static CredentialProofValidationFailureReason MapResolutionFailure(HeaderKeyResolutionStatus status) =>
        status switch
        {
            HeaderKeyResolutionStatus.JwkContainsPrivateKey => CredentialProofValidationFailureReason.JwkContainsPrivateKey,
            HeaderKeyResolutionStatus.KeyReferenceUnresolved => CredentialProofValidationFailureReason.KeyReferenceUnresolved,
            _ => CredentialProofValidationFailureReason.InvalidKeyReference
        };


    //Projects the jwk members (string-valued in a proof header) into the string dictionary the
    //RFC 7638 thumbprint helper consumes.
    private static Dictionary<string, string> ToStringValuedJwk(Dictionary<string, object> jwkMembers)
    {
        Dictionary<string, string> stringValued = new(jwkMembers.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> member in jwkMembers)
        {
            if(member.Value is string value)
            {
                stringValued[member.Key] = value;
            }
        }

        return stringValued;
    }
}
