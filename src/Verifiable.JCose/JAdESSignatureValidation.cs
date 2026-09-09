using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The strict JAdES B-B signature validation orchestrator: parses wire bytes across any of the three JWS
/// serializations, decodes the JWS Protected Header through the JAdES-typed codec, checks every B-B conformance
/// rule, resolves the verification payload per the signature's attachment/<c>sigD</c> mechanism, and verifies the
/// JWS signature value over it, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope boundary.</strong> This is structural conformance plus cryptographic verification with
/// caller-provided key material — clause 5.1 and clause 5.2 B-B rules only, mirroring
/// <see cref="JAdESHeaderRules"/>'s own scope. Table 1's level-conditioned requirements, time-stamp-token
/// message-imprint binding, and any EN 319 102-1 Indication/SubIndication mapping are the level-aware overloads'
/// territory, not this class's. Certificate-path trust and revocation are never resolved or validated — <c>kid</c> is a
/// non-authoritative hint and drives no key selection; the caller supplies the verification key by whatever
/// means it trusts, exactly like <see cref="Jws.VerifyAsync(JwsMessage, EncodeDelegate, PublicKeyMemory, CancellationToken)"/>
/// does for a plain JWS.
/// </para>
/// <para>
/// <strong>Never throws on malformed or non-conformant input.</strong> Every failure mode reachable from
/// untrusted wire bytes — a parse failure, a protected-header decode failure, a B-B rule violation, an
/// unresolvable detached object, a digest mismatch, a bad signature — is reported as a
/// <see cref="JAdESValidationResult"/> with <see cref="JAdESValidationResult.IsValid"/> <see langword="false"/>,
/// never a thrown exception. <see cref="ArgumentNullException"/> for a missing REQUIRED delegate/key/pool
/// parameter is a caller-contract violation, not a conformance judgment, and remains a thrown exception.
/// </para>
/// <para>
/// <strong>Signature verification uses the wire bytes captured at parse.</strong> <see cref="UnverifiedJAdESMessage"/>
/// (via its <see cref="UnverifiedJAdESMessage.Wire"/> member) carries the protected header's own base64url TEXT
/// verbatim (<see cref="UnverifiedJwsSignature.Protected"/>), and this class builds the RFC 7515 §5.1 Signing
/// Input from THAT text directly — never a re-encoding of the decoded <see cref="JAdESProtectedHeaders"/> model —
/// via <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, bool, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
/// (reuse discipline — this class never re-implements RFC 7515 §5.1/RFC 7797 §3 signing-input assembly).
/// </para>
/// <para>
/// <strong>THE promotion template.</strong> Parsing untrusted bytes produces <see cref="UnverifiedJAdESMessage"/>
/// (the JCose <c>Unverified*</c> family, extended by exactly the one genuinely new shape it needed — the
/// <c>etsiU</c> array's byte-exact raw carriage). A successful call promotes the decoded facts into a
/// <see cref="Verified{JAdESVerifiedSignatureFacts}"/> (<see cref="JAdESValidationResult.Verified"/>) — the ONE
/// route by which this library hands a relying party proof that verification succeeded. A failure reached after
/// the wire bytes and protected header decoded successfully still carries those decoded facts
/// (<see cref="JAdESValidationResult.Headers"/>/<see cref="JAdESValidationResult.UnsignedHeaders"/>), with
/// ownership exactly once — never duplicated onto both the failure arm and a (non-existent, on failure) promoted
/// value.
/// </para>
/// <para>
/// <strong>Payload resolution (clause 5.2.8), mirroring <see cref="JAdESSignatureCreation"/>'s own dispatch.</strong>
/// Exactly one of five cases applies once the B-B rules hold (JA-5.2.8.1-02/JA-5.1.9-04 jointly guarantee
/// <c>sigD</c> present implies the payload is detached):
/// </para>
/// <list type="number">
/// <item><description>Attached payload, no <c>sigD</c>: the wire payload bytes verify the signature directly.</description></item>
/// <item><description>
/// Detached payload, no <c>sigD</c>: <paramref name="externalDetachedPayload"/> (of the <c>ValidateAsync</c>
/// overloads below) supplies the out-of-band bytes; <see langword="null"/> there is
/// <see cref="JAdESDetachedObjectUnresolvableFailure"/>.
/// </description></item>
/// <item><description>
/// <c>sigD</c> selects <c>HttpHeaders</c>: the payload is re-canonicalized in-library from
/// <paramref name="httpHeadersContext"/> (of the <c>ValidateAsync</c> overloads below) via
/// <see cref="JAdESDetachedObjectDereferencing.Canonicalize"/> — no dereferencing, no seam; a
/// missing context or a context missing a referenced header value is <see cref="JAdESDetachedObjectUnresolvableFailure"/>.
/// </description></item>
/// <item><description>
/// <c>sigD</c> selects <c>ObjectIdByURI</c>: the payload is the order-preserving concatenation of every
/// dereferenced <c>pars</c> entry, reconstructed via
/// <see cref="JAdESDetachedObjectDereferencing.ReconstructObjectIdByUriPayloadAsync"/> (reuse, never
/// re-implemented); a dereference failure is <see cref="JAdESDetachedObjectUnresolvableFailure"/>.
/// </description></item>
/// <item><description>
/// <c>sigD</c> selects <c>ObjectIdByURIHash</c>: the payload contributes as an EMPTY stream to signature
/// verification (JA-5.2.8.3.3-05), and every <c>hashV</c> entry is independently re-verified against the
/// dereferenced object via the registered digest delegate resolved from <c>hashM</c> — any mismatch,
/// unresolvable dereference, or unresolvable digest algorithm fails the whole validation, even though the
/// signature-value check itself never sees these bytes.
/// </description></item>
/// </list>
/// <para>
/// An <c>mId</c> naming none of the three built-in mechanisms dispatches to the caller-supplied
/// <see cref="JAdESUnknownDetachedObjectMechanismDelegate"/> (JA-5.2.8.1-C1); absent or failing, that is
/// <see cref="JAdESDetachedObjectUnresolvableFailure"/> too — "failing" meaning exactly what that delegate's own
/// remarks document: a routine retrieval failure signalled by throwing
/// <see cref="JAdESDetachedObjectDereferenceException"/>, the only exception type this class's own catch around
/// that call narrows to. Anything else the handler raises is NOT caught here and propagates unmodified,
/// mirroring the creation side's own contract for the identical delegate exactly.
/// </para>
/// <para>
/// <strong><c>etsiU</c> is decoded structurally only.</strong> When <see cref="UnverifiedJAdESMessage.EtsiURawBytes"/>
/// is present, this class decodes it via <see cref="TryParseJAdESEtsiUDelegate"/> and exposes the result on
/// <see cref="JAdESValidationResult"/> so a relying party can see what unsigned components the signature
/// carries; it never re-checks a single JA-5.3.1 array-level rule (already enforced at
/// <see cref="JAdESUnsignedHeaders"/>'s own constructor) and never evaluates a Table 1 level rule or a
/// time-stamp-token message imprint against it — that is out of scope here.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "headers/unsignedHeaders ownership transfers to the returned JAdESValidationResult on every " +
        "explicit return below (either promoted through Verified<JAdESVerifiedSignatureFacts> on success, or " +
        "carried directly on a post-decode failure arm); the enclosing try/catch blocks " +
        "dispose them only on the non-explicit-return path (an unexpected exception), matching " +
        "CBAdESSignatureValidation's identical discipline one document removed.")]
public static class JAdESSignatureValidation
{
    /// <summary>
    /// Validates a JAdES signature using a registry-resolved verification function. Resolves
    /// <see cref="VerificationDelegate"/> from <paramref name="publicKey"/>'s tag and forwards to the explicit
    /// overload.
    /// </summary>
    /// <param name="wireBytes">The candidate JAdES wire bytes, any of the three JWS serializations.</param>
    /// <param name="parse">The fail-closed message parse seam (implemented in <c>Verifiable.Json</c>).</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed protected-header decode seam.</param>
    /// <param name="detectX5tPresence">The JA-5.1.6-01 wire-detection seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam; consulted only when the message carries one.</param>
    /// <param name="publicKey">The verifying public key; its tag selects the verification function.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding (the Signing Input's payload segment).</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference seam; needed only for the <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c> mechanisms.</param>
    /// <param name="dereferenceContext">The per-call context <paramref name="dereference"/> and <paramref name="unknownMechanismHandler"/> receive.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached JWS Payload bytes; needed only when the payload is detached and <c>sigD</c> is absent.</param>
    /// <param name="httpHeadersContext">The HTTP message facts to re-canonicalize; needed only when <c>sigD</c> selects <c>HttpHeaders</c>.</param>
    /// <param name="unknownMechanismHandler">Resolves the JWS Payload for a <c>sigD.mId</c> this document does not define.</param>
    /// <param name="pool">Memory pool for the transient parse and dereference buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey"/> is <see langword="null"/>.</exception>
    public static ValueTask<JAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        PublicKeyMemory publicKey,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return ValidateAsync(
            wireBytes, parse, decodeProtectedHeader, detectX5tPresence, parseEtsiU, publicKey, verificationDelegate,
            base64UrlDecoder, base64UrlEncoder, dereference, dereferenceContext, externalDetachedPayload,
            httpHeadersContext, unknownMechanismHandler, pool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Validates a JAdES signature using an explicit verification delegate — the core implementation. See the
    /// type remarks for the full algorithm and its certificate-path-neutral, level-agnostic scope boundary.
    /// B-B ONLY — see the level-aware overloads below for the Table 1/message-imprint extension.
    /// </summary>
    /// <param name="wireBytes">See the registry-resolved overload.</param>
    /// <param name="parse">See the registry-resolved overload.</param>
    /// <param name="decodeProtectedHeader">See the registry-resolved overload.</param>
    /// <param name="detectX5tPresence">See the registry-resolved overload.</param>
    /// <param name="parseEtsiU">See the registry-resolved overload.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="base64UrlDecoder">See the registry-resolved overload.</param>
    /// <param name="base64UrlEncoder">See the registry-resolved overload.</param>
    /// <param name="dereference">See the registry-resolved overload.</param>
    /// <param name="dereferenceContext">See the registry-resolved overload.</param>
    /// <param name="externalDetachedPayload">See the registry-resolved overload.</param>
    /// <param name="httpHeadersContext">See the registry-resolved overload.</param>
    /// <param name="unknownMechanismHandler">See the registry-resolved overload.</param>
    /// <param name="pool">Memory pool for the transient parse and dereference buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="parse"/>, <paramref name="decodeProtectedHeader"/>, <paramref name="detectX5tPresence"/>,
    /// <paramref name="parseEtsiU"/>, <paramref name="publicKey"/>, <paramref name="verificationDelegate"/>,
    /// <paramref name="base64UrlDecoder"/>, <paramref name="base64UrlEncoder"/>, or <paramref name="pool"/> is
    /// <see langword="null"/>.
    /// </exception>
    public static async ValueTask<JAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        JAdESCoreVerificationOutcome outcome = await VerifyStructureAndSignatureAsync(
            wireBytes, parse, decodeProtectedHeader, detectX5tPresence, parseEtsiU, publicKey, verificationDelegate,
            base64UrlDecoder, base64UrlEncoder, dereference, dereferenceContext, externalDetachedPayload,
            httpHeadersContext, unknownMechanismHandler, pool, cancellationToken).ConfigureAwait(false);

        if(!outcome.Succeeded)
        {
            return ToFailedResult(outcome);
        }

        //A B-B-only caller never consumes the level-aware carriers VerifyStructureAndSignatureAsync keeps alive
        //for the level pass (the parsed message and the archive-timestamp payload-source rental) -- both are
        //disposed immediately here, mirroring CBAdESSignatureValidation's identical B-B/level-aware split.
        outcome.Message!.Dispose();
        outcome.ArchiveTimestampPayloadSourceOwned?.Dispose();

        return JAdESValidationResult.Success(outcome.Headers!, outcome.PayloadIsDetached, outcome.UnsignedHeaders, AssertedProvenance.OfLabel(outcome.Headers!.KeyId));
    }


    /// <summary>
    /// Validates a JAdES signature against a supplied signing CERTIFICATE — the DEFAULT, RECOMMENDED
    /// B-B overload: resolves the verification key from <paramref name="signingCertificate"/> itself (never a
    /// caller-supplied raw key — the algorithm is read from the RESOLVED key via the crypto registry, never the
    /// wire <c>alg</c>), verifies the JWS signature value under it, then BINDS by recomputing the certificate's
    /// own digest and comparing it against the protected header's own signing-certificate-identification
    /// commitment (<c>x5t#S256</c>/<c>x5t#o</c>/<c>sigX5ts</c>). A
    /// successful call therefore mints an IDENTITY-BOUND <see cref="Verified{T}"/>
    /// (<see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/> on <see cref="JAdESValidationResult.Verified"/>),
    /// unlike the bare-<see cref="PublicKeyMemory"/> overloads above, which stay the honest bring-your-own-key
    /// primitive (never bound, an <see cref="AssertedProvenance"/> label only).
    /// </summary>
    /// <remarks>
    /// <strong>The forwarder guardrail.</strong> This overload runs the certificate-under-verify and
    /// the digest recompute itself, entirely inside this assembly's own binding boundary
    /// (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> is <see langword="internal"/>) — it never
    /// exposes a public entry point that accepts a caller-authored <see cref="SignatureCryptographicVerification"/>
    /// and binds from it, which would let a caller forge a match by authoring both sides of the recompute.
    /// </remarks>
    /// <param name="wireBytes">See the bare-key overload.</param>
    /// <param name="parse">See the bare-key overload.</param>
    /// <param name="decodeProtectedHeader">See the bare-key overload.</param>
    /// <param name="detectX5tPresence">See the bare-key overload.</param>
    /// <param name="parseEtsiU">See the bare-key overload.</param>
    /// <param name="signingCertificate">The DER-encoded candidate signing certificate.</param>
    /// <param name="base64UrlDecoder">See the bare-key overload.</param>
    /// <param name="base64UrlEncoder">See the bare-key overload.</param>
    /// <param name="dereference">See the bare-key overload.</param>
    /// <param name="dereferenceContext">See the bare-key overload.</param>
    /// <param name="externalDetachedPayload">See the bare-key overload.</param>
    /// <param name="httpHeadersContext">See the bare-key overload.</param>
    /// <param name="unknownMechanismHandler">See the bare-key overload.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, and digest-recompute buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="signingCertificate"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<JAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        PkiCertificateMemory signingCertificate,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(pool);

        if(!EllipticCurveSigningCertificateResolution.TryResolve(signingCertificate, out CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> publicKeyPoint))
        {
            //This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that
            //parse as well-formed X.509 -- nothing could even be attempted, so this is reported through this
            //overload's own binary valid/invalid vocabulary rather than a thrown exception.
            return JAdESValidationResult.Failed(new JAdESSigningCertificateBindingFailure(
                "This binding verifies only elliptic-curve signing certificates (P-256/P-384/P-521/secp256k1) that parse as well-formed X.509."));
        }

        using PublicKeyMemory publicKey = JAdESSignatureFacts.ToPublicKeyMemory(publicKeyPoint, algorithm, pool);
        CryptoAlgorithm verificationAlgorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(verificationAlgorithm, purpose);

        JAdESCoreVerificationOutcome outcome = await VerifyStructureAndSignatureAsync(
            wireBytes, parse, decodeProtectedHeader, detectX5tPresence, parseEtsiU, publicKey, verificationDelegate,
            base64UrlDecoder, base64UrlEncoder, dereference, dereferenceContext, externalDetachedPayload,
            httpHeadersContext, unknownMechanismHandler, pool, cancellationToken).ConfigureAwait(false);

        if(!outcome.Succeeded)
        {
            return ToFailedResult(outcome);
        }

        outcome.Message!.Dispose();
        outcome.ArchiveTimestampPayloadSourceOwned?.Dispose();

        return await BindAndMintAsync(
            outcome.Headers!, outcome.PayloadIsDetached, outcome.UnsignedHeaders, signingCertificate, level: null, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The certificate-accepting overloads' shared terminal step: builds the signature's own
    /// signing-certificate-identification references (<see cref="JAdESSignatureFacts.BuildSigningCertificateReferences"/>),
    /// binds by recomputing <paramref name="signingCertificate"/>'s digest against the signer reference among
    /// them (<see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>), and mints a
    /// <see cref="Verified{T}"/> ONLY when the recompute matches — fails closed
    /// (<see cref="JAdESSigningCertificateBindingFailure"/>) otherwise, never silently downgrading to an
    /// <see cref="AssertedProvenance"/> mint.
    /// </summary>
    /// <param name="headers">The already B-B-checked, cryptographically-verified signed-header-set aggregate. Ownership transfers into the returned result either way.</param>
    /// <param name="payloadIsDetached">Whether the JWS Payload this signature covers is detached.</param>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent. Ownership transfers into the returned result either way.</param>
    /// <param name="signingCertificate">The certificate the JWS signature value verified under.</param>
    /// <param name="level">The level this call was checking against, or <see langword="null"/> for the B-B-only overload.</param>
    /// <param name="pool">The memory pool the transient reference/digest buffers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A valid, identity-bound result, or a <see cref="JAdESSigningCertificateBindingFailure"/> result carrying <paramref name="headers"/>/<paramref name="unsignedHeaders"/>.</returns>
    private static async ValueTask<JAdESValidationResult> BindAndMintAsync(
        JAdESProtectedHeaders headers,
        bool payloadIsDetached,
        JAdESUnsignedHeaders? unsignedHeaders,
        PkiCertificateMemory signingCertificate,
        AdESBaselineLevel? level,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        var facts = new JAdESVerifiedSignatureFacts(headers, payloadIsDetached, unsignedHeaders, level);
        List<SigningCertificateReference> references = JAdESSignatureFacts.BuildSigningCertificateReferences(headers, pool);
        try
        {
            var cryptographicVerification = new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.Verified,
                SigningCertificate = signingCertificate
            };

            BoundProvenance? provenance = await BoundProvenance.TryBindByCertificateDigestAsync(
                references, cryptographicVerification, facts, pool, cancellationToken).ConfigureAwait(false);

            JAdESValidationResult? bound = provenance is null ? null : JAdESValidationResult.SuccessBound(facts, provenance);
            if(bound is not null)
            {
                return bound;
            }

            //The recompute did not match the protected header's own commitment (or, in the should-not-occur
            //case, the witness check itself refused) -- fail closed rather than silently downgrading to
            //Asserted. facts is a bare by-reference wrapper this method never disposed, so headers/
            //unsignedHeaders still need exactly the failure-arm carriage every other post-decode
            //failure in this class already gives them.
            return JAdESValidationResult.Failed(
                new JAdESSigningCertificateBindingFailure(
                    "The supplied signing certificate's recomputed digest does not match the protected header's " +
                    "own signing-certificate-identification commitment (x5t#S256/x5t#o/sigX5ts), or no such " +
                    "commitment resolves."),
                headers, unsignedHeaders, level);
        }
        finally
        {
            for(int i = 0; i < references.Count; ++i)
            {
                references[i].CertificateDigest?.Dispose();
            }
        }
    }


    /// <summary>
    /// Validates a JAdES signature at a specific <see cref="AdESBaselineLevel"/> using a registry-resolved
    /// verification function. Resolves <see cref="VerificationDelegate"/> from <paramref name="publicKey"/>'s
    /// tag and forwards to the explicit overload. Runs the identical B-B structural-plus-cryptographic core
    /// first (see the B-B-only overloads above), then additionally checks every Table 1 level-scoped rule
    /// (<see cref="JAdESLevelRules.Check"/>) and every electronic time-stamp token's message-imprint binding.
    /// </summary>
    /// <param name="wireBytes">The candidate JAdES wire bytes, any of the three JWS serializations.</param>
    /// <param name="parse">See the B-B-only overload.</param>
    /// <param name="decodeProtectedHeader">See the B-B-only overload.</param>
    /// <param name="detectX5tPresence">See the B-B-only overload.</param>
    /// <param name="parseEtsiU">See the B-B-only overload.</param>
    /// <param name="publicKey">The verifying public key; its tag selects the verification function.</param>
    /// <param name="base64UrlDecoder">See the B-B-only overload.</param>
    /// <param name="base64UrlEncoder">See the B-B-only overload.</param>
    /// <param name="dereference">See the B-B-only overload.</param>
    /// <param name="dereferenceContext">See the B-B-only overload.</param>
    /// <param name="externalDetachedPayload">See the B-B-only overload.</param>
    /// <param name="httpHeadersContext">See the B-B-only overload.</param>
    /// <param name="unknownMechanismHandler">See the B-B-only overload.</param>
    /// <param name="level">The baseline level to check against — the level a validation caller believes the signature claims (see <see cref="JAdESLevelRules"/>'s own remarks).</param>
    /// <param name="canonicalize">The registered canonicalization delegate, needed for every clear-JSON-incorporated <c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c> message-imprint input this pass builds.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, and token-verification buffers.</param>
    /// <param name="tryDecodeCounterSignature">
    /// Decodes a <c>cSig</c> element's own nested message for the JA-5.3.2 countersignature check
    /// (<see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/>). OPTIONAL — <see langword="null"/> (the
    /// default) leaves every <c>cSig</c> element structurally accepted (presence is never itself a violation)
    /// but neither decoded nor cryptographically verified, mirroring <see cref="CBAdESSignatureValidation"/>'s
    /// identical opt-in decode-delegate convention for its own counter-signature family. Supplying it opts in;
    /// <paramref name="resolvePublicKey"/> is then REQUIRED (see that parameter).
    /// </param>
    /// <param name="resolvePublicKey">
    /// Resolves a decoded <c>cSig</c> countersignature's public key. REQUIRED whenever <paramref name="tryDecodeCounterSignature"/>
    /// is supplied (an unresolvable key reports <see cref="JAdESCounterSignatureVerificationFailureReason.KeyUnresolved"/>
    /// rather than skipping verification, per <see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/>'s own
    /// contract); otherwise unused.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result; see the type remarks for the never-throws-on-untrusted-input contract.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey"/>, <paramref name="canonicalize"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static ValueTask<JAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        PublicKeyMemory publicKey,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        AdESBaselineLevel level,
        JAdESCanonicalizeUnsignedElementDelegate canonicalize,
        BaseMemoryPool pool,
        TryDecodeJAdESCounterSignatureDelegate? tryDecodeCounterSignature = null,
        ResolveJAdESCounterSignaturePublicKeyDelegate? resolvePublicKey = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return ValidateAsync(
            wireBytes, parse, decodeProtectedHeader, detectX5tPresence, parseEtsiU, publicKey, verificationDelegate,
            base64UrlDecoder, base64UrlEncoder, dereference, dereferenceContext, externalDetachedPayload,
            httpHeadersContext, unknownMechanismHandler, level, canonicalize, pool,
            tryDecodeCounterSignature, resolvePublicKey, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Validates a JAdES signature at a specific <see cref="AdESBaselineLevel"/> using an explicit verification
    /// delegate — the level-aware core implementation. See the registry-resolved overload's remarks.
    /// </summary>
    /// <param name="wireBytes">See the registry-resolved level-aware overload.</param>
    /// <param name="parse">See the B-B-only overload.</param>
    /// <param name="decodeProtectedHeader">See the B-B-only overload.</param>
    /// <param name="detectX5tPresence">See the B-B-only overload.</param>
    /// <param name="parseEtsiU">See the B-B-only overload.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="base64UrlDecoder">See the B-B-only overload.</param>
    /// <param name="base64UrlEncoder">See the B-B-only overload.</param>
    /// <param name="dereference">See the B-B-only overload.</param>
    /// <param name="dereferenceContext">See the B-B-only overload.</param>
    /// <param name="externalDetachedPayload">See the B-B-only overload.</param>
    /// <param name="httpHeadersContext">See the B-B-only overload.</param>
    /// <param name="unknownMechanismHandler">See the B-B-only overload.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="canonicalize">See the registry-resolved level-aware overload.</param>
    /// <param name="pool">Memory pool for the transient parse, dereference, and token-verification buffers.</param>
    /// <param name="tryDecodeCounterSignature">See the registry-resolved level-aware overload.</param>
    /// <param name="resolvePublicKey">See the registry-resolved level-aware overload.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="parse"/>, <paramref name="decodeProtectedHeader"/>, <paramref name="detectX5tPresence"/>,
    /// <paramref name="parseEtsiU"/>, <paramref name="publicKey"/>, <paramref name="verificationDelegate"/>,
    /// <paramref name="base64UrlDecoder"/>, <paramref name="base64UrlEncoder"/>, <paramref name="canonicalize"/>,
    /// or <paramref name="pool"/> is <see langword="null"/>; also <paramref name="resolvePublicKey"/> when
    /// <paramref name="tryDecodeCounterSignature"/> is supplied but this one is not.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <strong>Both incorporation modes verify identically.</strong>
    /// <c>etsiU</c>'s base64url-opaque carriage (<see cref="JAdESOpaqueUnsignedValue{TValue}"/>) carries a decoded
    /// view (<see cref="JAdESOpaqueUnsignedValue{TValue}.DecodedValue"/>) BESIDE its own wire TEXT — a
    /// decode-for-INSPECTION, never a decode-then-re-encode (that stays forbidden; see
    /// <see cref="JAdESOpaqueUnsignedValue{TValue}"/>'s own remarks on the §1.4 discipline). Per-instance CMS
    /// and message-imprint verification therefore runs REGARDLESS of <see cref="JAdESUnsignedHeaders.Mode"/>,
    /// reading each carriage's own decoded view; the message-imprint INPUT itself is still built exclusively by
    /// <see cref="JAdESMessageImprints"/>'s own already-mode-dispatching builders (base64url incorporation
    /// concatenates <see cref="JAdESOpaqueUnsignedValue{TValue}.WireText"/> verbatim via
    /// <c>ConcatenateOpaqueElements</c>, never the decoded view). The STRUCTURAL Table 1 rules
    /// (<see cref="JAdESLevelRules.Check"/> — presence, cardinality, the letter gates) run in full under either
    /// mode, as before.
    /// </para>
    /// <para>
    /// <strong>Prefix bounds, threaded from each instance's own array index.</strong> Every
    /// <c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c> instance's expected message-imprint input is built by
    /// <see cref="JAdESMessageImprints"/>'s VALIDATION builders, passing that instance's own zero-based position
    /// within <c>etsiU</c> as the exclusive prefix bound — a later sibling instance of the
    /// same kind, appended after this one, never changes what THIS instance is checked against. Those same
    /// builders independently assert the element at that position IS the expected arm and, under clear mode,
    /// that the supplied <c>canonAlg</c> equals the element's own declared one (structural linkage) —
    /// a mismatch surfaces as <see cref="JAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable"/>,
    /// never a silently-accepted input.
    /// </para>
    /// </remarks>
    public static async ValueTask<JAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        AdESBaselineLevel level,
        JAdESCanonicalizeUnsignedElementDelegate canonicalize,
        BaseMemoryPool pool,
        TryDecodeJAdESCounterSignatureDelegate? tryDecodeCounterSignature = null,
        ResolveJAdESCounterSignaturePublicKeyDelegate? resolvePublicKey = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(canonicalize);
        ArgumentNullException.ThrowIfNull(pool);

        JAdESCoreVerificationOutcome outcome = await VerifyStructureAndSignatureAsync(
            wireBytes, parse, decodeProtectedHeader, detectX5tPresence, parseEtsiU, publicKey, verificationDelegate,
            base64UrlDecoder, base64UrlEncoder, dereference, dereferenceContext, externalDetachedPayload,
            httpHeadersContext, unknownMechanismHandler, pool, cancellationToken).ConfigureAwait(false);

        if(!outcome.Succeeded)
        {
            return ToFailedResult(outcome, level);
        }

        using UnverifiedJAdESMessage message = outcome.Message!;
        JAdESProtectedHeaders headers = outcome.Headers!;
        JAdESUnsignedHeaders? unsignedHeaders = outcome.UnsignedHeaders;

        try
        {
            var violations = new List<JAdESRuleViolation>();
            bool anyEmbeddedValidationMaterial = false;

            if(unsignedHeaders is not null)
            {
                UnverifiedJwsSignature signature = message.Wire.Signatures[0];
                using PooledMemory signatureValueBase64UrlAscii = RentAsciiBytes(
                    base64UrlEncoder(signature.SignatureBytes.Memory.Span), CryptoTags.JAdESMessageImprintInput, pool);
                using PooledMemory protectedHeaderBase64UrlAscii = RentAsciiBytes(
                    signature.Protected, CryptoTags.JAdESMessageImprintInput, pool);

                for(int i = 0; i < unsignedHeaders.Count; ++i)
                {
                    //Runs in BOTH incorporation modes -- the
                    //per-instance CMS+imprint checks read each carriage's own decoded view (clear or opaque
                    //alike), while the imprint INPUT itself is built by the already-mode-dispatching
                    //JAdESMessageImprints builders (ConcatenateOpaqueElements over verbatim wire text under
                    //Base64Url). A switch EXPRESSION selecting which verify task to run, awaited once
                    //below -- the side effect (the violations list, the awaited call) lives outside the switch.
                    ValueTask<bool> embeddedTask = unsignedHeaders[i] switch
                    {
                        JAdESUnsignedHeaderElementSignatureTimestamp sigTst =>
                            VerifySignatureTimestampAsync(sigTst, signatureValueBase64UrlAscii.AsReadOnlyMemory(), i, violations, pool, cancellationToken),

                        JAdESUnsignedHeaderElementArchiveTimestamp arcTst when level == AdESBaselineLevel.BLTA =>
                            VerifyArchiveTimestampAsync(
                                arcTst, unsignedHeaders, i, protectedHeaderBase64UrlAscii.AsReadOnlyMemory(),
                                signatureValueBase64UrlAscii.AsReadOnlyMemory(), outcome.ArchiveTimestampPayloadSource,
                                canonicalize, violations, pool, cancellationToken),

                        //Below the declared B-LTA, arcTst's own IMPRINT is not load-bearing yet (write-strict
                        //at creation, JAdESBaselineLevelTable.ArcTst; read-tolerant here) -- only token
                        //shape/CMS-signature checks run, no expected imprint, mirroring CBAdESSignatureValidation's
                        //identical read-tolerance precedent.
                        JAdESUnsignedHeaderElementArchiveTimestamp arcTstBelowBlta =>
                            VerifyTimestampContainerShapeOnlyAsync(arcTstBelowBlta.Carriage, JAdESTimestampTokenBindingKind.ArchiveTimestamp, i, violations, pool, cancellationToken),

                        JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst =>
                            VerifySignatureAndReferencesTimestampAsync(sigRTst, unsignedHeaders, i, signatureValueBase64UrlAscii.AsReadOnlyMemory(), canonicalize, violations, pool, cancellationToken),

                        JAdESUnsignedHeaderElementReferencesTimestamp rfsTst =>
                            VerifyReferencesTimestampAsync(rfsTst, unsignedHeaders, i, canonicalize, violations, pool, cancellationToken),

                        _ => ValueTask.FromResult(false)
                    };

                    anyEmbeddedValidationMaterial |= await embeddedTask.ConfigureAwait(false);
                }
            }

            var levelContext = new JAdESLevelRuleContext
            {
                Level = level,
                UnsignedHeaders = unsignedHeaders,
                ProtectedHeaders = headers,
                SigningCertificateDigests = CollectSigningCertificateDigests(headers),
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = anyEmbeddedValidationMaterial
            };

            IReadOnlyList<JAdESRuleViolation> structuralLevelViolations = JAdESLevelRules.Check(levelContext);
            for(int i = 0; i < structuralLevelViolations.Count; ++i)
            {
                violations.Add(structuralLevelViolations[i]);
            }

            //Opt-in seam (the CBAdESSignatureValidation counter-signature precedent): a caller that never
            //supplies tryDecodeCounterSignature gets structural acceptance only -- JAdESHeaderRules/JAdESLevelRules
            //already never flag a cSig element's mere presence as a violation. Supplying it wires the SHIPPED
            //JAdESLevelRules.CheckCounterSignaturesAsync (previously unreachable from this orchestrator) into
            //the collected violations, exactly like CheckReferencesResolveToValidationDataAsync below.
            if(tryDecodeCounterSignature is not null)
            {
                IReadOnlyList<JAdESRuleViolation> counterSignatureViolations = await JAdESLevelRules.CheckCounterSignaturesAsync(
                    unsignedHeaders,
                    unsignedHeaders?.Mode ?? JAdESEtsiUIncorporationMode.ClearJson,
                    message.Wire.Signatures[0].SignatureBytes.Memory,
                    tryDecodeCounterSignature,
                    base64UrlDecoder,
                    base64UrlEncoder,
                    resolvePublicKey!,
                    pool,
                    cancellationToken).ConfigureAwait(false);

                for(int i = 0; i < counterSignatureViolations.Count; ++i)
                {
                    violations.Add(counterSignatureViolations[i]);
                }
            }

            //Unconditional (mirrors CBAdESSignatureValidation.CheckReferencesResolveToValidationDataAsync's own
            //wiring exactly): the check itself already gates on whether a refs-family trigger element is present
            //and on JAdESEtsiUIncorporationMode.ClearJson, so no caller opt-in is needed here.
            IReadOnlyList<JAdESRuleViolation> crossConsistencyViolations = await JAdESLevelRules
                .CheckReferencesResolveToValidationDataAsync(unsignedHeaders, pool, cancellationToken)
                .ConfigureAwait(false);
            for(int i = 0; i < crossConsistencyViolations.Count; ++i)
            {
                violations.Add(crossConsistencyViolations[i]);
            }

            if(violations.Count > 0)
            {
                return JAdESValidationResult.Failed(new JAdESRuleViolationsFailure(violations), headers, unsignedHeaders, level);
            }

            return JAdESValidationResult.Success(headers, outcome.PayloadIsDetached, unsignedHeaders, AssertedProvenance.OfLabel(headers.KeyId), level);
        }
        catch
        {
            headers.Dispose();
            unsignedHeaders?.Dispose();
            throw;
        }
        finally
        {
            outcome.ArchiveTimestampPayloadSourceOwned?.Dispose();
        }
    }


    /// <summary>
    /// Shapes a failed <see cref="JAdESCoreVerificationOutcome"/> into a <see cref="JAdESValidationResult"/>,
    /// threading <see cref="JAdESCoreVerificationOutcome.Headers"/>/<see cref="JAdESCoreVerificationOutcome.UnsignedHeaders"/>
    /// onward when the core decoded them before failing, rather than discarding them — the shared
    /// shaping every <c>ValidateAsync</c> overload's core-failure arm uses.
    /// </summary>
    /// <param name="outcome">The failed core outcome. <see cref="JAdESCoreVerificationOutcome.Succeeded"/> must be <see langword="false"/>.</param>
    /// <param name="level">The level a level-aware caller was checking against, or <see langword="null"/> for a B-B-only caller.</param>
    /// <returns>The shaped, invalid result.</returns>
    private static JAdESValidationResult ToFailedResult(JAdESCoreVerificationOutcome outcome, AdESBaselineLevel? level = null) =>
        outcome.Headers is not null
            ? JAdESValidationResult.Failed(outcome.Failure!, outcome.Headers, outcome.UnsignedHeaders, level)
            : JAdESValidationResult.Failed(outcome.Failure!);


    /// <summary>
    /// The shared structural-plus-cryptographic B-B core (the B-B-only explicit-delegate <c>ValidateAsync</c>
    /// overload's own algorithm exactly), extracted so both the B-B-only overloads and the level-aware
    /// overloads run the IDENTICAL parse/rule/payload-resolution/signature-verification pipeline — a level-aware
    /// caller then continues past <see cref="JAdESCoreVerificationOutcome.Succeeded"/> into the level pass; a
    /// B-B-only caller stops there.
    /// </summary>
    /// <remarks>
    /// On success, <see cref="JAdESCoreVerificationOutcome.Message"/> is left UNDISPOSED — the level-aware pass
    /// needs <c>message.Wire.Signatures[0]</c>'s own protected-header text and signature-value bytes to build
    /// message-imprint inputs. Every caller of this method (B-B-only or level-aware) disposes it exactly once.
    /// On every failure path this method disposes <paramref name="wireBytes"/>'s own parsed message itself before
    /// returning — nothing is left for a caller to double-dispose.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "message is disposed explicitly on every failure return below (a local Dispose() call " +
            "immediately preceding it, since no enclosing 'using' spans the whole method any more -- the level-" +
            "aware caller needs message to stay open past a successful return); on success it is handed onward, " +
            "undisposed, through the returned outcome's own Message member, owned from there by whichever caller " +
            "(B-B-only or level-aware) requested this core.")]
    private static async ValueTask<JAdESCoreVerificationOutcome> VerifyStructureAndSignatureAsync(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        DetectJAdESX5tPresenceDelegate detectX5tPresence,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(decodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(detectX5tPresence);
        ArgumentNullException.ThrowIfNull(parseEtsiU);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        bool parsed;
        UnverifiedJAdESMessage? message;
        try
        {
            parsed = parse(wireBytes.Span, base64UrlDecoder, pool, out message, out _);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            return JAdESCoreVerificationOutcome.Fail(new JAdESMalformedEncodingFailure());
        }

        if(!parsed || message is null)
        {
            return JAdESCoreVerificationOutcome.Fail(new JAdESMalformedEncodingFailure());
        }

        UnverifiedJwsSignature signature = message.Wire.Signatures[0];

        JAdESProtectedHeaders? decodedHeaders;
        bool x5tWasPresentOnWire;
        IMemoryOwner<byte>? protectedJsonBytes;
        try
        {
            protectedJsonBytes = base64UrlDecoder(signature.Protected, pool);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            message.Dispose();

            return JAdESCoreVerificationOutcome.Fail(new JAdESMalformedEncodingFailure());
        }

        using(protectedJsonBytes)
        {
            decodedHeaders = decodeProtectedHeader(protectedJsonBytes.Memory.Span, base64UrlDecoder, pool);
            if(decodedHeaders is null)
            {
                message.Dispose();

                return JAdESCoreVerificationOutcome.Fail(new JAdESMalformedEncodingFailure());
            }

            x5tWasPresentOnWire = detectX5tPresence(protectedJsonBytes.Memory.Span);
        }

        JAdESProtectedHeaders headers = decodedHeaders;

        try
        {
            bool payloadIsDetached = message.Wire.IsDetachedPayload;
            PooledMemory? etsiURawBytes = message.EtsiURawBytes;

            JAdESUnsignedHeaders? unsignedHeaders = null;
            if(etsiURawBytes is not null
                && (!parseEtsiU(etsiURawBytes.AsReadOnlySpan(), base64UrlDecoder, pool, out unsignedHeaders) || unsignedHeaders is null))
            {
                headers.Dispose();
                message.Dispose();

                return JAdESCoreVerificationOutcome.Fail(new JAdESMalformedEncodingFailure());
            }

            try
            {
                IReadOnlyList<JAdESRuleViolation> violations = JAdESHeaderRules.Check(headers, payloadIsDetached, x5tWasPresentOnWire: x5tWasPresentOnWire);
                if(violations.Count > 0)
                {
                    message.Dispose();

                    return JAdESCoreVerificationOutcome.Fail(new JAdESRuleViolationsFailure(violations), headers, unsignedHeaders);
                }

                (bool resolved, PooledMemory? rented, ReadOnlyMemory<byte> resolvedPayload, JAdESValidationFailure? resolutionFailure) =
                    await ResolveVerificationPayloadAsync(
                        message.Wire.Payload, headers, payloadIsDetached, dereference, dereferenceContext,
                        externalDetachedPayload, httpHeadersContext, unknownMechanismHandler, base64UrlEncoder,
                        pool, cancellationToken).ConfigureAwait(false);

                using(rented)
                {
                    if(!resolved)
                    {
                        message.Dispose();

                        return JAdESCoreVerificationOutcome.Fail(resolutionFailure!, headers, unsignedHeaders);
                    }

                    //JA-5.2.8.3.2-C4/-C5 (shared by ObjectIdByURIHash via JA-5.2.8.3.3-05/-06): the resolved
                    //payload for these two mechanisms IS ALREADY the exact stream that contributes to the
                    //JWS Signature Value computation -- ReconstructObjectIdByUriPayloadAsync performs the
                    //b64-conditional per-object encoding itself before concatenating. Re-applying the b64
                    //header parameter's own whole-payload encoding here (RFC 7797 SS3) on top of that would
                    //encode it a second time, producing a Signing Input no conformant peer would reproduce
                    //from the clause text -- see JAdESSignatureCreation.SignAsync's identical reasoning.
                    bool base64UrlPayload = headers.SigD is not (JAdESObjectIdByUriReference or JAdESObjectIdByUriHashReference)
                        && (headers.B64 is null || headers.B64.Value);

                    bool isValid = await Jws.VerifySignatureAsync(
                        signature.Protected,
                        resolvedPayload,
                        base64UrlPayload,
                        signature.SignatureBytes.Memory,
                        base64UrlEncoder,
                        verificationDelegate,
                        publicKey.AsReadOnlyMemory(),
                        pool,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    if(!isValid)
                    {
                        message.Dispose();

                        return JAdESCoreVerificationOutcome.Fail(new JAdESSignatureInvalidFailure(), headers, unsignedHeaders);
                    }

                    JAdESArchiveTimestampPayloadSource? archiveTimestampPayloadSource = null;
                    PooledMemory? archiveTimestampPayloadSourceOwned = null;
                    if(unsignedHeaders is not null && ContainsArchiveTimestampElement(unsignedHeaders))
                    {
                        (archiveTimestampPayloadSource, archiveTimestampPayloadSourceOwned) =
                            BuildArchiveTimestampPayloadSource(headers, resolvedPayload, base64UrlEncoder, pool);
                    }

                    return JAdESCoreVerificationOutcome.Ok(
                        message, headers, unsignedHeaders, payloadIsDetached, archiveTimestampPayloadSource, archiveTimestampPayloadSourceOwned);
                }
            }
            catch
            {
                unsignedHeaders?.Dispose();
                headers.Dispose();
                message.Dispose();
                throw;
            }
        }
        catch
        {
            headers.Dispose();
            message.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The facts <see cref="VerifyStructureAndSignatureAsync"/> hands both the B-B-only and level-aware
    /// <c>ValidateAsync</c> overloads. On failure, only <see cref="Failure"/> (plus, for a post-decode failure,
    /// <see cref="Headers"/>/<see cref="UnsignedHeaders"/>) is populated, and <see cref="Message"/> has already
    /// been disposed. On success, every member is populated and <see cref="Message"/> is left open for the
    /// level-aware pass — see that method's own remarks for the full ownership contract.
    /// </summary>
    private readonly struct JAdESCoreVerificationOutcome
    {
        /// <summary>Gets whether the B-B core succeeded.</summary>
        public bool Succeeded { get; private init; }

        /// <summary>Gets the still-open parsed message on success; <see langword="null"/> on failure (already disposed).</summary>
        public UnverifiedJAdESMessage? Message { get; private init; }

        /// <summary>Gets the decoded signed-header-set aggregate, when decoded before success or a post-decode failure.</summary>
        public JAdESProtectedHeaders? Headers { get; private init; }

        /// <summary>Gets the decoded <c>etsiU</c> set, when present.</summary>
        public JAdESUnsignedHeaders? UnsignedHeaders { get; private init; }

        /// <summary>Gets whether the JWS Payload this signature covers is detached.</summary>
        public bool PayloadIsDetached { get; private init; }

        /// <summary>
        /// Gets the <c>arcTst</c> message-imprint payload contribution (clause 5.3.6.2.3 steps 1-2), resolved once
        /// on success ONLY when <see cref="UnsignedHeaders"/> carries at least one <c>arcTst</c> element;
        /// <see langword="null"/> otherwise. Borrows <see cref="ArchiveTimestampPayloadSourceOwned"/>'s buffer.
        /// </summary>
        public JAdESArchiveTimestampPayloadSource? ArchiveTimestampPayloadSource { get; private init; }

        /// <summary>Gets the pool rental <see cref="ArchiveTimestampPayloadSource"/> borrows from, when resolved; the caller disposes it exactly once.</summary>
        public PooledMemory? ArchiveTimestampPayloadSourceOwned { get; private init; }

        /// <summary>Gets the failure detail on a failed outcome; <see langword="null"/> on success.</summary>
        public JAdESValidationFailure? Failure { get; private init; }


        /// <summary>Builds a successful outcome.</summary>
        public static JAdESCoreVerificationOutcome Ok(
            UnverifiedJAdESMessage message,
            JAdESProtectedHeaders headers,
            JAdESUnsignedHeaders? unsignedHeaders,
            bool payloadIsDetached,
            JAdESArchiveTimestampPayloadSource? archiveTimestampPayloadSource,
            PooledMemory? archiveTimestampPayloadSourceOwned) =>
            new()
            {
                Succeeded = true,
                Message = message,
                Headers = headers,
                UnsignedHeaders = unsignedHeaders,
                PayloadIsDetached = payloadIsDetached,
                ArchiveTimestampPayloadSource = archiveTimestampPayloadSource,
                ArchiveTimestampPayloadSourceOwned = archiveTimestampPayloadSourceOwned
            };


        /// <summary>Builds a failed outcome carrying no decoded facts (nothing decoded before the failure).</summary>
        public static JAdESCoreVerificationOutcome Fail(JAdESValidationFailure failure) => new() { Succeeded = false, Failure = failure };


        /// <summary>Builds a failed outcome that carries the decoded facts known at the point of failure.</summary>
        public static JAdESCoreVerificationOutcome Fail(JAdESValidationFailure failure, JAdESProtectedHeaders headers, JAdESUnsignedHeaders? unsignedHeaders) =>
            new() { Succeeded = false, Failure = failure, Headers = headers, UnsignedHeaders = unsignedHeaders };
    }


    /// <summary>Determines whether <paramref name="unsignedHeaders"/> carries at least one <c>arcTst</c> element — gates whether <see cref="VerifyStructureAndSignatureAsync"/> resolves the (potentially costly) archive-timestamp payload source at all.</summary>
    private static bool ContainsArchiveTimestampElement(JAdESUnsignedHeaders unsignedHeaders)
    {
        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(unsignedHeaders[i] is JAdESUnsignedHeaderElementArchiveTimestamp)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint payload contribution (clause 5.3.6.2.3 steps 1-2) from the
    /// already-resolved verification payload: <see cref="JAdESSigDProcessedPayloadImprintSource"/> when
    /// <c>sigD</c> is present (the SAME bytes signature verification just used); otherwise
    /// <see cref="JAdESRawPayloadImprintSource"/> when <c>b64</c> is present-and-<see langword="false"/>, or
    /// <see cref="JAdESBase64UrlPayloadImprintSource"/> (a fresh base64url re-encode) otherwise. Always copies
    /// into a fresh pool rental the caller owns — <paramref name="resolvedPayload"/> may alias a buffer about to
    /// be disposed by its own caller's <c>using</c> scope.
    /// </summary>
    private static (JAdESArchiveTimestampPayloadSource Source, PooledMemory Owned) BuildArchiveTimestampPayloadSource(
        JAdESProtectedHeaders headers, ReadOnlyMemory<byte> resolvedPayload, EncodeDelegate base64UrlEncoder, BaseMemoryPool pool)
    {
        if(headers.SigD is not null)
        {
            PooledMemory owned = PooledMemory.FromBytes(resolvedPayload.Span, pool, CryptoTags.JAdESMessageImprintInput);

            return (new JAdESSigDProcessedPayloadImprintSource(owned.AsReadOnlyMemory()), owned);
        }

        if(headers.B64 is { } b64 && !b64)
        {
            PooledMemory owned = PooledMemory.FromBytes(resolvedPayload.Span, pool, CryptoTags.JAdESMessageImprintInput);

            return (new JAdESRawPayloadImprintSource(owned.AsReadOnlyMemory()), owned);
        }

        PooledMemory ownedText = RentAsciiBytes(base64UrlEncoder(resolvedPayload.Span), CryptoTags.JAdESMessageImprintInput, pool);

        return (new JAdESBase64UrlPayloadImprintSource(ownedText.AsReadOnlyMemory()), ownedText);
    }


    /// <summary>
    /// Collects every signing-certificate digest hint the JWS Protected Header itself asserts
    /// (<see cref="JAdESProtectedHeaders.X5tHashS256"/>, <see cref="JAdESProtectedHeaders.X5tHashO"/>, every
    /// <see cref="JAdESProtectedHeaders.SigX5ts"/> entry) — the JA-A.1.1-02 <c>xRefs</c> self-reference exclusion
    /// check's own input. Certificate-path neutral: <see cref="JAdESProtectedHeaders.X5Chain"/> (full DER
    /// certificates, not digests) is deliberately never consulted here, mirroring
    /// <see cref="CBAdESSignatureValidation"/>'s identical X5T-hint-only posture.
    /// </summary>
    private static List<DigestValue>? CollectSigningCertificateDigests(JAdESProtectedHeaders headers)
    {
        var digests = new List<DigestValue>();

        if(headers.X5tHashS256 is not null)
        {
            digests.Add(headers.X5tHashS256);
        }

        if(headers.X5tHashO is not null)
        {
            digests.Add(headers.X5tHashO.Digest);
        }

        if(headers.SigX5ts is not null)
        {
            for(int i = 0; i < headers.SigX5ts.Thumbprints.Count; ++i)
            {
                digests.Add(headers.SigX5ts.Thumbprints[i].Digest);
            }
        }

        return digests.Count > 0 ? digests : null;
    }


    /// <summary>
    /// Extracts the decoded time-stamp container from either arm of the dual-mode carriage:
    /// verification runs in BOTH incorporation modes, reading each
    /// carrier's own decoded view (<see cref="JAdESClearUnsignedValue{TValue}.Value"/> or
    /// <see cref="JAdESOpaqueUnsignedValue{TValue}.DecodedValue"/>) — never re-deriving the message-imprint
    /// input from it (that stays the exclusive concern of <see cref="JAdESMessageImprints"/>'s own
    /// mode-dispatching builders, which read <see cref="JAdESOpaqueUnsignedValue{TValue}.WireText"/> instead).
    /// </summary>
    private static AdESTimestampContainer GetDecodedTimestampContainer(JAdESUnsignedValue<AdESTimestampContainer> carriage) => carriage switch
    {
        JAdESClearUnsignedValue<AdESTimestampContainer> clear => clear.Value,
        JAdESOpaqueUnsignedValue<AdESTimestampContainer> opaque => opaque.DecodedValue,
        _ => throw new NotSupportedException($"Unknown etsiU carriage arm '{carriage.GetType()}'.")
    };


    /// <summary>Verifies a <c>sigTst</c> instance's token(s) against the expected imprint (JA-5.3.4-04: the base64url-encoded JWS Signature Value, verbatim — no separate builder needed). Runs in both incorporation modes.</summary>
    private static async ValueTask<bool> VerifySignatureTimestampAsync(
        JAdESUnsignedHeaderElementSignatureTimestamp sigTst,
        ReadOnlyMemory<byte> signatureValueBase64UrlAscii,
        int instanceOrdinal,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        AdESTimestampContainer decoded = GetDecodedTimestampContainer(sigTst.Carriage);

        return await VerifyTimestampContainerAsync(
            decoded, JAdESTimestampTokenBindingKind.SignatureTimestamp, signatureValueBase64UrlAscii,
            instanceOrdinal, violations, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Opens and CMS-verifies every token of a <c>tstContainer</c>-bearing carriage with no expected imprint (below-B-LTA <c>arcTst</c>, JAdESSignatureValidation's own read-tolerance). Runs in both incorporation modes.</summary>
    private static async ValueTask<bool> VerifyTimestampContainerShapeOnlyAsync(
        JAdESUnsignedValue<AdESTimestampContainer> carriage,
        JAdESTimestampTokenBindingKind kind,
        int instanceOrdinal,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        AdESTimestampContainer decoded = GetDecodedTimestampContainer(carriage);

        return await VerifyTimestampContainerAsync(
            decoded, kind, expectedImprintInput: null, instanceOrdinal, violations, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint input in validation mode (JAdESMessageImprints, prefix-bound
    /// to this instance's own array position), then verifies every token of the instance's <c>tstContainer</c>
    /// against it. Runs in both incorporation modes; under
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/> the imprint input is built by
    /// <see cref="JAdESMessageImprints"/>'s own already-mode-dispatching builder (<c>ConcatenateOpaqueElements</c>
    /// over verbatim wire text) — <c>canonAlg</c>/the canonicalize delegate are forced <see langword="null"/> here
    /// since JA-5.3.1-15 forbids either under base64url incorporation.
    /// </summary>
    private static async ValueTask<bool> VerifyArchiveTimestampAsync(
        JAdESUnsignedHeaderElementArchiveTimestamp arcTst,
        JAdESUnsignedHeaders etsiU,
        int elementIndex,
        ReadOnlyMemory<byte> protectedHeaderBase64UrlAscii,
        ReadOnlyMemory<byte> signatureValueBase64UrlAscii,
        JAdESArchiveTimestampPayloadSource? payloadSource,
        JAdESCanonicalizeUnsignedElementDelegate canonicalize,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        AdESTimestampContainer decoded = GetDecodedTimestampContainer(arcTst.Carriage);
        bool isClearMode = etsiU.Mode == JAdESEtsiUIncorporationMode.ClearJson;

        if(payloadSource is null)
        {
            violations.Add(new JAdESTimestampTokenBindingViolation(
                JAdESTimestampTokenBindingKind.ArchiveTimestamp, JAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                "The arcTst message-imprint input's payload contribution (clause 5.3.6.2.3 steps 1-2) could not be resolved.",
                elementIndex, TokenOrdinal: -1));

            return false;
        }

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = payloadSource,
            ProtectedHeaderBase64Url = protectedHeaderBase64UrlAscii,
            SignatureValueBase64Url = signatureValueBase64UrlAscii,
            CanonAlg = isClearMode ? decoded.CanonAlg : null,
            Canonicalize = isClearMode ? canonicalize : null
        };

        PooledMemory imprintInput;
        try
        {
            imprintInput = await JAdESMessageImprints.BuildArchiveTimestampValidationMessageImprintInputAsync(
                context, etsiU, elementIndex, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(ArgumentException ex)
        {
            violations.Add(new JAdESTimestampTokenBindingViolation(
                JAdESTimestampTokenBindingKind.ArchiveTimestamp, JAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                ex.Message, elementIndex, TokenOrdinal: -1));

            return false;
        }

        using(imprintInput)
        {
            return await VerifyTimestampContainerAsync(
                decoded, JAdESTimestampTokenBindingKind.ArchiveTimestamp, imprintInput.AsReadOnlyMemory(),
                elementIndex, violations, pool, cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>Builds the <c>sigRTst</c> message-imprint input in validation mode (prefix-bound to this instance's own position), then verifies every token against it. Runs in both incorporation modes.</summary>
    private static async ValueTask<bool> VerifySignatureAndReferencesTimestampAsync(
        JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst,
        JAdESUnsignedHeaders etsiU,
        int elementIndex,
        ReadOnlyMemory<byte> signatureValueBase64UrlAscii,
        JAdESCanonicalizeUnsignedElementDelegate canonicalize,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        AdESTimestampContainer decoded = GetDecodedTimestampContainer(sigRTst.Carriage);
        bool isClearMode = etsiU.Mode == JAdESEtsiUIncorporationMode.ClearJson;

        PooledMemory imprintInput;
        try
        {
            imprintInput = await JAdESMessageImprints.BuildSignatureAndReferencesTimestampValidationMessageImprintInputAsync(
                signatureValueBase64UrlAscii, etsiU, elementIndex,
                isClearMode ? decoded.CanonAlg : null, isClearMode ? canonicalize : null, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(ArgumentException ex)
        {
            violations.Add(new JAdESTimestampTokenBindingViolation(
                JAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp, JAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                ex.Message, elementIndex, TokenOrdinal: -1));

            return false;
        }

        using(imprintInput)
        {
            return await VerifyTimestampContainerAsync(
                decoded, JAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp, imprintInput.AsReadOnlyMemory(),
                elementIndex, violations, pool, cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>Builds the <c>rfsTst</c> message-imprint input in validation mode (prefix-bound to this instance's own position), then verifies every token against it. Runs in both incorporation modes.</summary>
    private static async ValueTask<bool> VerifyReferencesTimestampAsync(
        JAdESUnsignedHeaderElementReferencesTimestamp rfsTst,
        JAdESUnsignedHeaders etsiU,
        int elementIndex,
        JAdESCanonicalizeUnsignedElementDelegate canonicalize,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        AdESTimestampContainer decoded = GetDecodedTimestampContainer(rfsTst.Carriage);
        bool isClearMode = etsiU.Mode == JAdESEtsiUIncorporationMode.ClearJson;

        PooledMemory imprintInput;
        try
        {
            imprintInput = await JAdESMessageImprints.BuildReferencesOnlyTimestampValidationMessageImprintInputAsync(
                etsiU, elementIndex, isClearMode ? decoded.CanonAlg : null, isClearMode ? canonicalize : null, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(ArgumentException ex)
        {
            violations.Add(new JAdESTimestampTokenBindingViolation(
                JAdESTimestampTokenBindingKind.ReferencesTimestamp, JAdESTimestampTokenBindingFailureReason.ImprintInputUnresolvable,
                ex.Message, elementIndex, TokenOrdinal: -1));

            return false;
        }

        using(imprintInput)
        {
            return await VerifyTimestampContainerAsync(
                decoded, JAdESTimestampTokenBindingKind.ReferencesTimestamp, imprintInput.AsReadOnlyMemory(),
                elementIndex, violations, pool, cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Opens and CMS-verifies every token of <paramref name="container"/>, appending a
    /// <see cref="JAdESTimestampTokenBindingViolation"/> for a token that could not be read or whose message
    /// imprint does not match <paramref name="expectedImprintInput"/> (when supplied). EVERY token in
    /// <paramref name="container"/> is checked against the SAME <paramref name="expectedImprintInput"/> (letter l:
    /// an <c>arcTst</c> instance may carry more than one token, one per configured Time-Stamping Authority leg).
    /// </summary>
    /// <param name="container">The <c>tstContainer</c> to verify.</param>
    /// <param name="kind">Which token kind <paramref name="container"/> belongs to.</param>
    /// <param name="expectedImprintInput">The expected message-imprint input, or <see langword="null"/> to skip imprint verification entirely and only check that every token opens and CMS-verifies.</param>
    /// <param name="instanceOrdinal">This <c>etsiU</c> element's own zero-based position, attributing which instance of a repeated kind <paramref name="container"/> belongs to (Table 1 NOTE 7).</param>
    /// <param name="violations">The violation list to append to.</param>
    /// <param name="pool">Memory pool for the token and digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> when at least one successfully-opened token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifyTimestampContainerAsync(
        AdESTimestampContainer container,
        JAdESTimestampTokenBindingKind kind,
        ReadOnlyMemory<byte>? expectedImprintInput,
        int instanceOrdinal,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        bool anyEmbedded = false;
        for(int t = 0; t < container.TstTokens.Count; ++t)
        {
            anyEmbedded |= await VerifyOneTimestampTokenAsync(
                container.TstTokens[t], kind, expectedImprintInput, instanceOrdinal, t, violations, pool, cancellationToken).ConfigureAwait(false);
        }

        return anyEmbedded;
    }


    /// <summary>
    /// Opens and CMS-verifies one electronic time-stamp token via the single CMS choke point
    /// (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>) and checks — when <paramref name="expectedImprintInput"/>
    /// is supplied — that its message imprint binds it (<see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/>).
    /// </summary>
    /// <returns><see langword="true"/> when the token opened and carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
    private static async ValueTask<bool> VerifyOneTimestampTokenAsync(
        AdESTimestampToken token,
        JAdESTimestampTokenBindingKind kind,
        ReadOnlyMemory<byte>? expectedImprintInput,
        int instanceOrdinal,
        int tokenOrdinal,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using PkiCertificateMemory tokenMemory = RentTimestampTokenMemory(token.Val, pool);
        using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(tokenMemory, pool, cancellationToken).ConfigureAwait(false);

        if(!tokenInfo.IsRead)
        {
            violations.Add(new JAdESTimestampTokenBindingViolation(
                kind, JAdESTimestampTokenBindingFailureReason.TokenNotRead,
                $"The token could not be read (status: {tokenInfo.Status}).", instanceOrdinal, tokenOrdinal));

            return false;
        }

        if(expectedImprintInput is not null)
        {
            bool imprintMatches = await tokenInfo.VerifyMessageImprintAsync(expectedImprintInput.Value, pool, cancellationToken).ConfigureAwait(false);
            if(!imprintMatches)
            {
                violations.Add(new JAdESTimestampTokenBindingViolation(
                    kind, JAdESTimestampTokenBindingFailureReason.ImprintMismatch,
                    "The token's message imprint does not match the expected input.", instanceOrdinal, tokenOrdinal));
            }
        }

        return tokenInfo.HasEmbeddedCertificates;
    }


    /// <summary>
    /// Copies <paramref name="tokenValue"/> into pool-rented memory and wraps it as a <see cref="PkiCertificateMemory"/>
    /// tagged <see cref="PkiCertificateTags.TimestampToken"/> (<see cref="AdESTimestampToken.Val"/> is a
    /// borrowed view this class does not itself own).
    /// </summary>
    /// <remarks>
    /// Internal, not private (mirroring the CB-AdES precedent): <see cref="JAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>
    /// reuses this SAME helper to open an <c>arcTst</c> instance's own tokens for the JA-A.1.1-12/-A.1.2-35/
    /// -A.1.3-08/-A.1.4-10 candidate-set widening, rather than re-implementing the identical copy-into-pooled-
    /// carrier shape a second time — both classes live in this same assembly (<c>Verifiable.JCose</c>).
    /// </remarks>
    internal static PkiCertificateMemory RentTimestampTokenMemory(ReadOnlyMemory<byte> tokenValue, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(tokenValue.Length, 1));
        try
        {
            tokenValue.Span.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>Rents a pooled buffer and writes <paramref name="text"/> as ASCII octets — the wire-text-preservation carrier <see cref="CryptoTags.JAdESMessageImprintInput"/> label (no naked intermediate array), mirroring <see cref="JAdESSignatureAugmentation"/>'s own private helper of the same name.</summary>
    private static PooledMemory RentAsciiBytes(string text, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(text.Length, 1));
        try
        {
            Encoding.ASCII.GetBytes(text, owner.Memory.Span);

            return new PooledMemory(owner, text.Length, tag);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Resolves the verification payload per clause 5.2.8's five cases (see the type remarks) and, for the
    /// <c>ObjectIdByURIHash</c> case, independently re-verifies every <c>hashV</c> entry. A switch expression
    /// over <see cref="JAdESProtectedHeaders.SigD"/>'s closed sum, each arm a no-closure-capture <see langword="static"/>
    /// local function (contract IRON RULES).
    /// </summary>
    /// <returns>
    /// A tuple: whether resolution succeeded; a <see cref="PooledMemory"/> the caller must dispose when a
    /// mechanism rented one (<see langword="null"/> otherwise); the resolved payload view (valid only when
    /// resolution succeeded); the failure detail (valid only when resolution failed).
    /// </returns>
    private static ValueTask<(bool Resolved, PooledMemory? Rented, ReadOnlyMemory<byte> Payload, JAdESValidationFailure? Failure)> ResolveVerificationPayloadAsync(
        ReadOnlyMemory<byte> payload,
        JAdESProtectedHeaders headers,
        bool payloadIsDetached,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        ReadOnlyMemory<byte>? externalDetachedPayload,
        JAdESHttpHeadersCanonicalizationContext? httpHeadersContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        static ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> Ok(ReadOnlyMemory<byte> bytes, PooledMemory? rented = null) =>
            ValueTask.FromResult<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)>((true, rented, bytes, null));

        static ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> Fail(string? reference, string reason) =>
            ValueTask.FromResult<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)>(
                (false, null, default, new JAdESDetachedObjectUnresolvableFailure(reference, reason)));

        static async ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> ResolveDetachedNoSigDAsync(
            ReadOnlyMemory<byte>? external) =>
            external.HasValue
                ? await Ok(external.Value).ConfigureAwait(false)
                : await Fail(null, "The JWS Payload is detached and sigD is absent, but no out-of-band detached " +
                    "payload was supplied (ETSI TS 119 182-1 V1.2.1, clause 5.2.6 / clause 4.5).").ConfigureAwait(false);

        static async ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> ResolveHttpHeadersAsync(
            JAdESHttpHeadersReference httpHeaders, JAdESHttpHeadersCanonicalizationContext? context, BaseMemoryPool pool)
        {
            if(context is null)
            {
                return await Fail(null, "sigD selects HttpHeaders, but no canonicalization context was supplied " +
                    "(ETSI TS 119 182-1 V1.2.1, clause 5.2.8.2).").ConfigureAwait(false);
            }

            try
            {
                PooledMemory canonicalized = JAdESDetachedObjectDereferencing.Canonicalize(httpHeaders, context, pool);

                return await Ok(canonicalized.AsReadOnlyMemory(), canonicalized).ConfigureAwait(false);
            }
            catch(ArgumentException ex)
            {
                return await Fail(null, ex.Message).ConfigureAwait(false);
            }
        }

        static async ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> ResolveObjectIdByUriAsync(
            JAdESObjectIdByUriReference objectIdByUri, bool? b64, JAdESDetachedObjectDereferenceDelegate? dereference,
            JAdESDetachedObjectDereferenceContext? context, EncodeDelegate base64UrlEncoder, BaseMemoryPool pool,
            CancellationToken cancellationToken)
        {
            if(dereference is null || context is null)
            {
                return await Fail(null, "sigD selects ObjectIdByURI, but no dereference delegate/context was " +
                    "supplied (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.1).").ConfigureAwait(false);
            }

            try
            {
                bool base64UrlEncodeEachObject = b64 is null || b64.Value;
                var references = new JAdESDetachedObjectReferenceInput[objectIdByUri.References.Count];
                for(int i = 0; i < references.Length; ++i)
                {
                    references[i] = new JAdESDetachedObjectReferenceInput(objectIdByUri.References[i].Reference, objectIdByUri.References[i].ContentType);
                }

                PooledMemory reconstructed = await JAdESDetachedObjectDereferencing.ReconstructObjectIdByUriPayloadAsync(
                    references, base64UrlEncodeEachObject, dereference, context, base64UrlEncoder, pool, cancellationToken).ConfigureAwait(false);

                return await Ok(reconstructed.AsReadOnlyMemory(), reconstructed).ConfigureAwait(false);
            }
            catch(JAdESDetachedObjectDereferenceException ex)
            {
                return await Fail(ex.UriReference, ex.Message).ConfigureAwait(false);
            }
        }

        static async ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> ResolveObjectIdByUriHashAsync(
            JAdESObjectIdByUriHashReference objectIdByUriHash, JAdESDetachedObjectDereferenceDelegate? dereference,
            JAdESDetachedObjectDereferenceContext? context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            if(dereference is null || context is null)
            {
                return await Fail(null, "sigD selects ObjectIdByURIHash, but no dereference delegate/context was " +
                    "supplied (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.1).").ConfigureAwait(false);
            }

            JAdESValidationFailure? digestFailure = await VerifyObjectIdByUriHashDigestsAsync(
                objectIdByUriHash, dereference, context, pool, cancellationToken).ConfigureAwait(false);

            if(digestFailure is not null)
            {
                return (false, null, default, digestFailure);
            }

            //JA-5.2.8.3.3-05: the JWS Payload contributes as an empty stream to signature verification,
            //regardless of the digest-verification outcome computed above.
            return await Ok(ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        }

        static async ValueTask<(bool, PooledMemory?, ReadOnlyMemory<byte>, JAdESValidationFailure?)> ResolveUnknownMechanismAsync(
            JAdESUnknownDetachedDataObjectReference unknown, JAdESDetachedObjectDereferenceContext? context,
            JAdESUnknownDetachedObjectMechanismDelegate? handler, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            if(context is null)
            {
                return await Fail(null, $"sigD.mId '{unknown.MechanismIdentifier}' is not one of the three " +
                    "mechanisms this document defines by name, and no dereference context was supplied (ETSI TS " +
                    "119 182-1 V1.2.1, clause 5.2.8.1, JA-5.2.8.1-C1).").ConfigureAwait(false);
            }

            if(handler is null)
            {
                return await Fail(null, $"sigD.mId '{unknown.MechanismIdentifier}' is not one of the three " +
                    "mechanisms this document defines by name, and no unknown-mechanism handler was supplied " +
                    "(ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, JA-5.2.8.1-C1).").ConfigureAwait(false);
            }

            try
            {
                var references = new JAdESDetachedObjectReferenceInput[unknown.References.Count];
                for(int i = 0; i < references.Length; ++i)
                {
                    references[i] = new JAdESDetachedObjectReferenceInput(unknown.References[i].Reference, unknown.References[i].ContentType);
                }

                PooledMemory handled = await handler(
                    unknown.MechanismIdentifier, references, unknown.HashAlgorithm, context, pool, cancellationToken).ConfigureAwait(false);

                return await Ok(handled.AsReadOnlyMemory(), handled).ConfigureAwait(false);
            }
            catch(JAdESDetachedObjectDereferenceException ex)
            {
                string reason = ex.UriReference is not null
                    ? $"The unknown-mechanism handler for sigD.mId '{unknown.MechanismIdentifier}' failed to retrieve '{ex.UriReference}': {ex.Message}"
                    : $"The unknown-mechanism handler for sigD.mId '{unknown.MechanismIdentifier}' failed: {ex.Message}";

                return await Fail(ex.UriReference, reason).ConfigureAwait(false);
            }
        }

        if(headers.SigD is null)
        {
            return payloadIsDetached ? ResolveDetachedNoSigDAsync(externalDetachedPayload) : Ok(payload);
        }

        return headers.SigD switch
        {
            JAdESHttpHeadersReference httpHeaders => ResolveHttpHeadersAsync(httpHeaders, httpHeadersContext, pool),
            JAdESObjectIdByUriReference objectIdByUri => ResolveObjectIdByUriAsync(objectIdByUri, headers.B64, dereference, dereferenceContext, base64UrlEncoder, pool, cancellationToken),
            JAdESObjectIdByUriHashReference objectIdByUriHash => ResolveObjectIdByUriHashAsync(objectIdByUriHash, dereference, dereferenceContext, pool, cancellationToken),
            JAdESUnknownDetachedDataObjectReference unknown => ResolveUnknownMechanismAsync(unknown, dereferenceContext, unknownMechanismHandler, pool, cancellationToken),
            _ => Fail(null, "Unrecognized sigD reference kind.")
        };
    }


    /// <summary>
    /// Independently re-verifies every <c>hashV</c> entry of an <c>ObjectIdByURIHash</c> <c>sigD</c> against the
    /// dereferenced object it references, via the registered digest delegate resolved from <c>hashM</c>
    /// (JA-5.2.8.3.3-04) — reuses <see cref="JAdESSignatureCreation.ResolveDigestParameters"/> rather than
    /// duplicating the SHA-256/384/512 resolution.
    /// </summary>
    /// <returns><see langword="null"/> when every entry verifies; otherwise the failure to report.</returns>
    private static async ValueTask<JAdESValidationFailure?> VerifyObjectIdByUriHashDigestsAsync(
        JAdESObjectIdByUriHashReference sigD,
        JAdESDetachedObjectDereferenceDelegate dereference,
        JAdESDetachedObjectDereferenceContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        (Tag DigestTag, int OutputByteLength) algorithm;
        try
        {
            algorithm = JAdESSignatureCreation.ResolveDigestParameters(sigD.HashAlgorithm);
        }
        catch(NotSupportedException ex)
        {
            return new JAdESDetachedObjectUnresolvableFailure(null, ex.Message);
        }

        for(int i = 0; i < sigD.References.Count; ++i)
        {
            cancellationToken.ThrowIfCancellationRequested();

            JAdESReferencedDataObject entry = sigD.References[i];

            JAdESDetachedObjectDereferenceResult dereferenced = await dereference(
                entry.Reference, context, pool, cancellationToken).ConfigureAwait(false);

            if(dereferenced is not JAdESDetachedObjectDereferenceSuccess success)
            {
                string reason = dereferenced is JAdESDetachedObjectDereferenceFailure failure
                    ? failure.Reason
                    : "the dereference delegate returned neither a success nor a failure result.";

                return new JAdESDetachedObjectUnresolvableFailure(entry.Reference, reason);
            }

            using(success.Content)
            {
                //entry.Digest is guaranteed non-null here: JAdESObjectIdByUriHashReference's own constructor
                //requires every entry to carry one (JA-5.2.8.3.3-04, JAdESHeaderRules's "satisfied by
                //construction" posture).
                using DigestValue recomputed = await CryptographicKeyEvents.ComputeDigestAsync(
                    success.Content.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if(!recomputed.AsReadOnlySpan().SequenceEqual(entry.Digest!.AsReadOnlySpan()))
                {
                    return new JAdESDetachedObjectDigestMismatchFailure(entry.Reference);
                }
            }
        }

        return null;
    }


    //FormatException/ArgumentException/InvalidOperationException/OverflowException -- never JsonException
    //(the STJ-body firewall: Verifiable.JCose stays STJ-free, so this file cannot even name that type). Every
    //JAdES JSON codec implementer (JAdESProtectedHeaderJson, JAdESMessageJson) already narrows its OWN
    //try/catch to its full fail-closed set including JsonException before returning failure/false across this
    //seam; this outer catch is the defensive boundary for a non-conformant future implementer, mirroring
    //CBAdESSignatureValidation's identical belt-and-suspenders posture one document removed.
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is FormatException or ArgumentException or InvalidOperationException or OverflowException;
}
