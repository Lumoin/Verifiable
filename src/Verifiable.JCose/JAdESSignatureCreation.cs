using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The JWS Payload input a JAdES B-B creation call signs over — the closed sum
/// <see cref="JAdESSignatureCreation"/> dispatches on to resolve both the bytes the JWS Signing Input actually
/// covers and the wire <c>payload</c> field's attached/detached shape (JA-4-07), mirroring
/// <see cref="CBAdESSigningPayloadInput"/> one document removed. A DU-ready closed sum: no external type may
/// derive from it.
/// </summary>
/// <remarks>
/// Six concrete arms: <see cref="JAdESAttachedPayloadInput"/> (attached, no <c>sigD</c>),
/// <see cref="JAdESDetachedExternalPayloadInput"/> (detached, no <c>sigD</c> — an out-of-band-agreed payload,
/// clause 4.5's analogue for JAdES), and one arm per <c>sigD</c> mechanism —
/// <see cref="JAdESDetachedHttpHeadersPayloadInput"/> (clause 5.2.8.2), <see cref="JAdESDetachedObjectIdByUriPayloadInput"/>
/// (clause 5.2.8.3.2), <see cref="JAdESDetachedObjectIdByUriHashPayloadInput"/> (clause 5.2.8.3.3), and
/// <see cref="JAdESDetachedUnknownMechanismPayloadInput"/> (the JA-5.2.8.1-C1 open extension point).
/// </remarks>
public abstract class JAdESSigningPayloadInput
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected JAdESSigningPayloadInput()
    {
    }
}


/// <summary>An attached JWS Payload (JA-4-07): the bytes both become the wire <c>payload</c> field and are what the Signing Input covers.</summary>
[DebuggerDisplay("JAdESAttachedPayloadInput: {Payload.Length} bytes")]
public sealed class JAdESAttachedPayloadInput : JAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="JAdESAttachedPayloadInput"/>.</summary>
    /// <param name="payload">The payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory for the duration of the call.</param>
    public JAdESAttachedPayloadInput(ReadOnlyMemory<byte> payload)
    {
        Payload = payload;
    }

    /// <summary>The payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory for the duration of the call.</summary>
    public ReadOnlyMemory<byte> Payload { get; }
}


/// <summary>A detached JWS Payload agreed out of band, without a <c>sigD</c> header parameter.</summary>
[DebuggerDisplay("JAdESDetachedExternalPayloadInput: {Payload.Length} bytes")]
public sealed class JAdESDetachedExternalPayloadInput : JAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="JAdESDetachedExternalPayloadInput"/>.</summary>
    /// <param name="payload">The bytes the Signing Input covers. <strong>Borrowed</strong> view. The wire <c>payload</c> field is omitted.</param>
    public JAdESDetachedExternalPayloadInput(ReadOnlyMemory<byte> payload)
    {
        Payload = payload;
    }

    /// <summary>The bytes the Signing Input covers. <strong>Borrowed</strong> view. The wire <c>payload</c> field is omitted.</summary>
    public ReadOnlyMemory<byte> Payload { get; }
}


/// <summary>The <c>HttpHeaders</c> mechanism of <c>sigD</c> (clause 5.2.8.2): in-library canonicalization, no dereferencing.</summary>
[DebuggerDisplay("JAdESDetachedHttpHeadersPayloadInput: {HeaderNames.Count} headers")]
public sealed class JAdESDetachedHttpHeadersPayloadInput : JAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="JAdESDetachedHttpHeadersPayloadInput"/>.</summary>
    /// <param name="headerNames">The <c>pars</c> member: lowercased HTTP header field names, in wire order (JA-5.2.8.2-04/-05).</param>
    /// <param name="context">The HTTP message facts to canonicalize; see <see cref="JAdESHttpHeadersCanonicalizationContext"/>.</param>
    public JAdESDetachedHttpHeadersPayloadInput(IReadOnlyList<string> headerNames, JAdESHttpHeadersCanonicalizationContext context)
    {
        HeaderNames = headerNames;
        Context = context;
    }

    /// <summary>The <c>pars</c> member: lowercased HTTP header field names, in wire order (JA-5.2.8.2-04/-05).</summary>
    public IReadOnlyList<string> HeaderNames { get; }

    /// <summary>The HTTP message facts to canonicalize; see <see cref="JAdESHttpHeadersCanonicalizationContext"/>.</summary>
    public JAdESHttpHeadersCanonicalizationContext Context { get; }
}


/// <summary>The <c>ObjectIdByURI</c> mechanism of <c>sigD</c> (clause 5.2.8.3.2): dereferenced, no digests.</summary>
[DebuggerDisplay("JAdESDetachedObjectIdByUriPayloadInput: {References.Count} references")]
public sealed class JAdESDetachedObjectIdByUriPayloadInput : JAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="JAdESDetachedObjectIdByUriPayloadInput"/>.</summary>
    /// <param name="references">The <c>pars</c> entries, in wire order (JA-5.2.8.1-16/-17).</param>
    public JAdESDetachedObjectIdByUriPayloadInput(IReadOnlyList<JAdESDetachedObjectReferenceInput> references)
    {
        References = references;
    }

    /// <summary>The <c>pars</c> entries, in wire order (JA-5.2.8.1-16/-17).</summary>
    public IReadOnlyList<JAdESDetachedObjectReferenceInput> References { get; }
}


/// <summary>
/// The <c>ObjectIdByURIHash</c> mechanism of <c>sigD</c> (clause 5.2.8.3.3): the "hashV-less" per-call input —
/// no digest travels in yet, because <see cref="JAdESSignatureCreation"/> computes it (JA-5.2.8.3.3-04).
/// </summary>
[DebuggerDisplay("JAdESDetachedObjectIdByUriHashPayloadInput: {HashAlgorithm}, {References.Count} references")]
public sealed class JAdESDetachedObjectIdByUriHashPayloadInput : JAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="JAdESDetachedObjectIdByUriHashPayloadInput"/>.</summary>
    /// <param name="hashAlgorithm">The <c>hashM</c> value (JA-5.2.8.1-18/-19) — resolves through the registered digest delegate; only SHA-256/384/512 are supported.</param>
    /// <param name="references">The <c>pars</c> entries, in wire order (JA-5.2.8.1-16/-17).</param>
    public JAdESDetachedObjectIdByUriHashPayloadInput(string hashAlgorithm, IReadOnlyList<JAdESDetachedObjectReferenceInput> references)
    {
        HashAlgorithm = hashAlgorithm;
        References = references;
    }

    /// <summary>The <c>hashM</c> value (JA-5.2.8.1-18/-19) — resolves through the registered digest delegate; only SHA-256/384/512 are supported.</summary>
    public string HashAlgorithm { get; }

    /// <summary>The <c>pars</c> entries, in wire order (JA-5.2.8.1-16/-17).</summary>
    public IReadOnlyList<JAdESDetachedObjectReferenceInput> References { get; }
}


/// <summary>A <c>sigD</c> mechanism this document does not itself define — the open extension point JA-5.2.8.1-C1 reserves.</summary>
[DebuggerDisplay("JAdESDetachedUnknownMechanismPayloadInput: {MechanismIdentifier}")]
public sealed class JAdESDetachedUnknownMechanismPayloadInput : JAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="JAdESDetachedUnknownMechanismPayloadInput"/>.</summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> value, verbatim.</param>
    /// <param name="references">The <c>pars</c> entries, in wire order.</param>
    /// <param name="hashAlgorithm">The caller-declared <c>hashM</c>, or <see langword="null"/>.</param>
    public JAdESDetachedUnknownMechanismPayloadInput(string mechanismIdentifier, IReadOnlyList<JAdESDetachedObjectReferenceInput> references, string? hashAlgorithm = null)
    {
        MechanismIdentifier = mechanismIdentifier;
        References = references;
        HashAlgorithm = hashAlgorithm;
    }

    /// <summary>The <c>mId</c> value, verbatim.</summary>
    public string MechanismIdentifier { get; }

    /// <summary>The <c>pars</c> entries, in wire order.</summary>
    public IReadOnlyList<JAdESDetachedObjectReferenceInput> References { get; }

    /// <summary>The caller-declared <c>hashM</c>, or <see langword="null"/>.</summary>
    public string? HashAlgorithm { get; }
}


/// <summary>
/// The outcome of <see cref="JAdESSignatureCreation.SignAsync"/>: the signed <see cref="JwsMessage"/> together
/// with the signed-header-set aggregate that was actually encoded — mirroring <see cref="CBAdESSignatureCreationResult"/>.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns both <see cref="Message"/> and <see cref="Headers"/>;
/// <see cref="Dispose"/> disposes both. The caller must dispose ONLY this result after a successful call — never
/// the original <c>headers</c> argument passed to <see cref="JAdESSignatureCreation.SignAsync"/>, since ownership
/// of that argument transfers to this call and <see cref="Headers"/> shares owned members with it.
/// </remarks>
[DebuggerDisplay("JAdESSignatureCreationResult: alg={Headers.Algorithm}")]
public sealed class JAdESSignatureCreationResult : IDisposable
{
    private bool disposed;


    /// <summary>Initializes a new <see cref="JAdESSignatureCreationResult"/>. Ownership of both arguments transfers to this instance.</summary>
    /// <param name="message">See <see cref="Message"/>.</param>
    /// <param name="headers">See <see cref="Headers"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="message"/> or <paramref name="headers"/> is <see langword="null"/>.</exception>
    public JAdESSignatureCreationResult(JwsMessage message, JAdESProtectedHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(headers);

        Message = message;
        Headers = headers;
    }


    /// <summary>Gets the signed JWS message. Owned by this instance; disposed via <see cref="Dispose"/>.</summary>
    public JwsMessage Message { get; }

    /// <summary>
    /// Gets the signed-header-set aggregate that was actually encoded into <see cref="Message"/>'s protected
    /// header — identical to the <c>headers</c> argument <see cref="JAdESSignatureCreation.SignAsync"/> received
    /// when no <c>sigD</c> completion was needed, or a new instance carrying the completed
    /// <see cref="JAdESProtectedHeaders.SigD"/> otherwise. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public JAdESProtectedHeaders Headers { get; }


    /// <summary>Disposes <see cref="Message"/> and <see cref="Headers"/>.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Message.Dispose();
            Headers.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// Creates a JAdES-B-B signature (ETSI TS 119 182-1 V1.2.1): composes <see cref="Jws"/>'s signing-input/signing
/// primitives over a <see cref="JAdESProtectedHeaders"/> aggregate, the shared <see cref="JAdESHeaderRules"/> rule
/// surface, q1's <see cref="EncodeJAdESProtectedHeaderDelegate"/>/<see cref="EncodeJAdESUnprotectedHeaderDelegate"/>
/// codec seams, and (for a <c>sigD</c>-referenced payload) <see cref="JAdESDetachedObjectDereferencing"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two throw-posture rule passes, mirroring <see cref="CBAdESSignatureCreation"/>'s identical
/// structure.</strong> <see cref="JAdESDetachedDataObjectReference"/>'s own per-mechanism constructors make a
/// "digest-less <c>ObjectIdByURIHash</c>" input unrepresentable, so this orchestrator resolves the payload BEFORE
/// it can build a complete <see cref="JAdESProtectedHeaders.SigD"/>. PASS 1 runs
/// <see cref="JAdESHeaderRules.EnsureConformant"/> on the caller-supplied <c>headers</c> as-is (whose <c>SigD</c>
/// is always <see langword="null"/> at this point) — every rule not depending on the resolved mechanism, strictly
/// before any dereferencing I/O. PASS 2 re-checks the fully-merged <c>effectiveHeaders</c> immediately before
/// signing.
/// </para>
/// <para>
/// <strong>This orchestrator is the SOLE producer of <see cref="JAdESProtectedHeaders.SigD"/>.</strong> A
/// caller-supplied <c>headers</c> whose <see cref="JAdESProtectedHeaders.SigD"/> is already non-null is refused —
/// the reference set travels through <paramref name="payloadInput"/>'s <c>sigD</c>-mechanism arms instead.
/// </para>
/// <para>
/// <strong>Creation is conformant by construction.</strong> When <paramref name="payloadInput"/> resolves a
/// <c>sigD</c> reference set, this orchestrator auto-adds <c>"sigD"</c> to
/// <see cref="JAdESProtectedHeaders.CriticalLabels"/> if not already present (JA-5.1.9-04/-05) — the caller never
/// has to remember this coupling. It does NOT auto-set <see cref="JAdESProtectedHeaders.B64"/>: the
/// <c>HttpHeaders</c> mechanism's <c>b64:false</c> coupling (JA-5.1.10-04) is enforced, not silently applied,
/// since flipping <c>b64</c> changes signing semantics the caller must decide explicitly.
/// </para>
/// <para>
/// <strong><c>b64</c> governs <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c>'s mechanism behavior, never a second
/// Signing-Input encoding on top of it.</strong> <see cref="JAdESProtectedHeaders.B64"/> (absent-or-true =
/// <see langword="true"/>) decides whether <c>ObjectIdByURI</c> base64url-re-encodes each retrieved object
/// before concatenation (JA-5.2.8.3.2-C4); the resulting concatenated stream (JA-5.2.8.3.2-C5) IS ALREADY the
/// exact bytes that contribute to the JWS Signature Value computation, so this method always builds the Signing
/// Input from it verbatim for these two mechanisms — never through
/// <see cref="Jws.RentSigningInput(string, ReadOnlySpan{byte}, bool, EncodeDelegate, BaseMemoryPool, out int)"/>'s
/// own <c>base64UrlPayload: true</c> arm, which would base64url-encode the whole already-encoded stream a
/// second time. Every other <see cref="JAdESSigningPayloadInput"/> arm (attached, external-detached, and
/// <c>HttpHeaders</c>, which forces <c>b64:false</c> itself) reads <c>b64</c> the ordinary RFC 7797 §3 way,
/// exactly once.
/// </para>
/// <para>
/// Serialization to a wire form is a SEPARATE step: <see cref="Serialize"/> composes
/// <see cref="JwsSerialization.Serialize"/> after checking JA-4-05 (an unprotected header forbids Compact
/// serialization) — this class never re-implements per-form byte layout.
/// </para>
/// </remarks>
public static class JAdESSignatureCreation
{
    /// <summary>Creates a JAdES-B-B signature using registry-resolved signing function.</summary>
    /// <param name="headers">The signed-header-set aggregate. Its <see cref="JAdESProtectedHeaders.SigD"/> shall be <see langword="null"/> — see the class remarks. Ownership transfers to this call on success.</param>
    /// <param name="payloadInput">The JWS Payload to sign over; see <see cref="JAdESSigningPayloadInput"/>.</param>
    /// <param name="unsignedHeaders">The <c>etsiU</c> set to incorporate, or <see langword="null"/> to omit it.</param>
    /// <param name="encodeProtectedHeader">The protected-header JSON encode seam.</param>
    /// <param name="encodeUnprotectedHeader">The unprotected-header (<c>etsiU</c>) projection seam.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="dereference">The <c>sigD</c> URI-reference dereference delegate; required for the <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c> arms.</param>
    /// <param name="dereferenceContext">The per-call caller state; required whenever <paramref name="payloadInput"/> needs dereferencing.</param>
    /// <param name="unknownMechanismHandler">The extension point for a third-party <c>mId</c>.</param>
    /// <param name="pool">Memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature creation result. The caller owns and disposes it.</returns>
    public static ValueTask<JAdESSignatureCreationResult> SignAsync(
        JAdESProtectedHeaders headers,
        JAdESSigningPayloadInput payloadInput,
        JAdESUnsignedHeaders? unsignedHeaders,
        EncodeJAdESProtectedHeaderDelegate encodeProtectedHeader,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return SignAsync(
            headers, payloadInput, unsignedHeaders, encodeProtectedHeader, encodeUnprotectedHeader,
            base64UrlEncoder, privateKey, signingDelegate, dereference, dereferenceContext,
            unknownMechanismHandler, pool, cancellationToken: cancellationToken);
    }


    /// <summary>Creates a JAdES-B-B signature using an explicit signing delegate.</summary>
    /// <param name="headers">See the registry-resolved overload.</param>
    /// <param name="payloadInput">See the registry-resolved overload.</param>
    /// <param name="unsignedHeaders">See the registry-resolved overload.</param>
    /// <param name="encodeProtectedHeader">See the registry-resolved overload.</param>
    /// <param name="encodeUnprotectedHeader">See the registry-resolved overload.</param>
    /// <param name="base64UrlEncoder">See the registry-resolved overload.</param>
    /// <param name="privateKey">See the registry-resolved overload.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="dereference">See the registry-resolved overload.</param>
    /// <param name="dereferenceContext">See the registry-resolved overload.</param>
    /// <param name="unknownMechanismHandler">See the registry-resolved overload.</param>
    /// <param name="pool">See the registry-resolved overload.</param>
    /// <param name="eventSink">Receives the produced <see cref="SignatureProducedEvent"/>, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature creation result. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">Any required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="headers"/>.<see cref="JAdESProtectedHeaders.SigD"/> is already non-null; a <c>sigD</c>-mechanism
    /// arm was supplied with no <paramref name="dereferenceContext"/>; or at least one B-B rule is violated (naming the clause).
    /// </exception>
    /// <exception cref="NotSupportedException">An unsupported <c>hashM</c> was supplied, or an unrecognized <c>mId</c> was supplied with no <paramref name="unknownMechanismHandler"/> (JA-5.2.8.1-C1).</exception>
    /// <exception cref="JAdESDetachedObjectDereferenceException">A referenced detached object could not be dereferenced.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "CompleteHeaders returns a new JAdESProtectedHeaders sharing every unchanged member -- " +
            "X5tHashS256, X5tHashO, SigX5ts, PayloadTimestamps, SignaturePolicyIdentifier -- by reference with " +
            "the caller-owned `headers` argument; only SigD/CriticalLabels are genuinely new. `headers` (and " +
            "therefore every shared member) transfers to the returned JAdESSignatureCreationResult on success; " +
            "the catch clause below disposes resolution.SigD -- the one internally-built member -- on every " +
            "failure path. effectiveHeaders itself is never disposed directly on either path.")]
    public static async ValueTask<JAdESSignatureCreationResult> SignAsync(
        JAdESProtectedHeaders headers,
        JAdESSigningPayloadInput payloadInput,
        JAdESUnsignedHeaders? unsignedHeaders,
        EncodeJAdESProtectedHeaderDelegate encodeProtectedHeader,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        EncodeDelegate base64UrlEncoder,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        JAdESDetachedObjectDereferenceDelegate? dereference,
        JAdESDetachedObjectDereferenceContext? dereferenceContext,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(payloadInput);
        ArgumentNullException.ThrowIfNull(encodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        if(headers.SigD is not null)
        {
            throw new ArgumentException(
                "This orchestrator is the sole producer of SigD (see the class remarks) -- supply the sigD " +
                "reference set through payloadInput's sigD-mechanism arm instead of pre-populating headers.SigD.",
                nameof(headers));
        }

        bool payloadIsDetached = payloadInput is not JAdESAttachedPayloadInput;

        //PASS 1 -- see the class remarks for why this runs before any dereferencing I/O, and why a second pass
        //follows mechanism resolution.
        JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached);

        bool base64UrlEncodeEachObject = headers.B64 is null || headers.B64.Value;

        PayloadResolution resolution = await ResolvePayloadAsync(
            payloadInput, base64UrlEncodeEachObject, dereference, dereferenceContext, unknownMechanismHandler,
            base64UrlEncoder, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            JAdESProtectedHeaders effectiveHeaders = resolution.SigD is null
                ? headers
                : CompleteHeaders(headers, resolution.SigD);

            //PASS 2 -- the final gate, immediately before signing.
            JAdESHeaderRules.EnsureConformant(effectiveHeaders, payloadIsDetached);

            string protectedSegment;
            using(EncodedJoseProtectedHeader encodedProtectedHeader = encodeProtectedHeader(effectiveHeaders, base64UrlEncoder, pool))
            {
                protectedSegment = Encoding.ASCII.GetString(encodedProtectedHeader.AsReadOnlySpan()[..encodedProtectedHeader.Length]);
            }

            //JA-5.2.8.3.2-C4/-C5 (shared by ObjectIdByURIHash via JA-5.2.8.3.3-05/-06): ResolvePayloadAsync
            //already produced the EXACT stream that contributes to the JWS Signature Value computation for
            //these two mechanisms -- the per-object b64-conditional encoding happened inside
            //JAdESDetachedObjectDereferencing.ReconstructObjectIdByUriPayloadAsync, not here. Re-applying the
            //b64 header parameter's own whole-payload RFC 7797 §3 encoding on top of that would encode the
            //stream a second time, producing a Signing Input no conformant peer building it from the clause
            //text would reproduce -- see JAdESSignatureValidation's identical reasoning on its own verify side.
            bool base64UrlPayload = effectiveHeaders.SigD is JAdESObjectIdByUriReference or JAdESObjectIdByUriHashReference
                ? false
                : effectiveHeaders.B64 is null || effectiveHeaders.B64.Value;

            using IMemoryOwner<byte> signingInputOwner = Jws.RentSigningInput(
                protectedSegment, resolution.SigningPayload.Span, base64UrlPayload, base64UrlEncoder, pool, out int signingInputLength);

            (Signature signature, CryptoEvent? signedEvent) = await signingDelegate(
                privateKey.AsReadOnlyMemory(),
                signingInputOwner.Memory[..signingInputLength],
                pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            if(signedEvent is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(signedEvent);
            }

            IReadOnlyDictionary<string, object>? unprotectedHeader = encodeUnprotectedHeader(unsignedHeaders);
            var protectedHeaderDictionary = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = effectiveHeaders.Algorithm };

            var component = new JwsSignatureComponent(protectedSegment, protectedHeaderDictionary, signature, unprotectedHeader);
            var message = new JwsMessage(
                payloadIsDetached ? ReadOnlyMemory<byte>.Empty : resolution.SigningPayload,
                component,
                payloadIsDetached);

            return new JAdESSignatureCreationResult(message, effectiveHeaders);
        }
        catch
        {
            (resolution.SigD as IDisposable)?.Dispose();
            throw;
        }
        finally
        {
            resolution.RentedSigningPayload?.Dispose();
        }
    }


    /// <summary>
    /// Serializes a <see cref="JAdESSignatureCreationResult"/> to <paramref name="format"/>, enforcing JA-4-05
    /// (an unprotected header forbids Compact serialization) before delegating to
    /// <see cref="JwsSerialization.Serialize"/> — this method never re-implements per-form byte layout (reuse
    /// over reinvention).
    /// </summary>
    /// <param name="result">The creation result to serialize.</param>
    /// <param name="format">The target serialization form.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing the JSON forms.</param>
    /// <returns>The serialized JAdES signature, UTF-8/ASCII bytes.</returns>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="format"/> is <see cref="JoseSerializationFormat.Compact"/> and <paramref name="result"/>
    /// carries a non-empty JWS Unprotected Header (ETSI TS 119 182-1 V1.2.1, clause 4, JA-4-05).
    /// </exception>
    public static byte[] Serialize(
        JAdESSignatureCreationResult result,
        JoseSerializationFormat format,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer)
    {
        ArgumentNullException.ThrowIfNull(result);

        if(format == JoseSerializationFormat.Compact
            && result.Message.Signatures[0].UnprotectedHeader is { Count: > 0 })
        {
            throw new ArgumentException(
                "A JAdES signature carrying a JWS Unprotected Header can only be serialized using JWS JSON " +
                "Serialization (ETSI TS 119 182-1 V1.2.1, clause 4, JA-4-05).",
                nameof(format));
        }

        return JwsSerialization.Serialize(result.Message, format, base64UrlEncoder, jsonSerializer);
    }


    /// <summary>The resolved payload: the completed <c>sigD</c> reference (when applicable), the Signing Input bytes, and any pool-rented buffer to dispose.</summary>
    private readonly record struct PayloadResolution(
        JAdESDetachedDataObjectReference? SigD,
        ReadOnlyMemory<byte> SigningPayload,
        PooledMemory? RentedSigningPayload);


    /// <summary>Resolves <paramref name="input"/> into the bytes the Signing Input covers and the completed <c>sigD</c> reference, when applicable.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each JAdESDetachedDataObjectReference this method constructs is returned as " +
            "PayloadResolution.SigD: ownership either transfers into the completed JAdESProtectedHeaders " +
            "aggregate the calling method builds, or is disposed by that method's own catch clause on failure.")]
    private static async ValueTask<PayloadResolution> ResolvePayloadAsync(
        JAdESSigningPayloadInput input,
        bool base64UrlEncodeEachObject,
        JAdESDetachedObjectDereferenceDelegate? dereferenceDelegate,
        JAdESDetachedObjectDereferenceContext? context,
        JAdESUnknownDetachedObjectMechanismDelegate? unknownHandler,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        switch(input)
        {
            case JAdESAttachedPayloadInput attached:
                return new PayloadResolution(null, attached.Payload, null);

            case JAdESDetachedExternalPayloadInput external:
                return new PayloadResolution(null, external.Payload, null);

            case JAdESDetachedHttpHeadersPayloadInput httpHeaders:
                {
                    var reference = new JAdESHttpHeadersReference(httpHeaders.HeaderNames);
                    PooledMemory canonicalized = JAdESDetachedObjectDereferencing.Canonicalize(reference, httpHeaders.Context, pool);
                    return new PayloadResolution(reference, canonicalized.AsReadOnlyMemory(), canonicalized);
                }

            case JAdESDetachedObjectIdByUriPayloadInput objectIdByUri:
                {
                    RequireDereference(dereferenceDelegate, context, "ObjectIdByURI", out JAdESDetachedObjectDereferenceDelegate checkedDereference, out JAdESDetachedObjectDereferenceContext checkedContext);
                    PooledMemory reconstructed = await JAdESDetachedObjectDereferencing.ReconstructObjectIdByUriPayloadAsync(
                        objectIdByUri.References, base64UrlEncodeEachObject, checkedDereference, checkedContext,
                        base64UrlEncoder, pool, cancellationToken).ConfigureAwait(false);

                    var entries = new List<JAdESReferencedDataObject>(objectIdByUri.References.Count);
                    for(int i = 0; i < objectIdByUri.References.Count; ++i)
                    {
                        entries.Add(new JAdESReferencedDataObject(objectIdByUri.References[i].Reference, objectIdByUri.References[i].ContentType));
                    }

                    var reference = new JAdESObjectIdByUriReference(entries);
                    return new PayloadResolution(reference, reconstructed.AsReadOnlyMemory(), reconstructed);
                }

            case JAdESDetachedObjectIdByUriHashPayloadInput objectIdByUriHash:
                {
                    RequireDereference(dereferenceDelegate, context, "ObjectIdByURIHash", out JAdESDetachedObjectDereferenceDelegate checkedDereference, out JAdESDetachedObjectDereferenceContext checkedContext);
                    (Tag digestTag, int outputByteLength) = ResolveDigestParameters(objectIdByUriHash.HashAlgorithm);

                    var entries = new List<JAdESReferencedDataObject>(objectIdByUriHash.References.Count);
                    try
                    {
                        for(int i = 0; i < objectIdByUriHash.References.Count; ++i)
                        {
                            cancellationToken.ThrowIfCancellationRequested();

                            JAdESDetachedObjectReferenceInput current = objectIdByUriHash.References[i];
                            JAdESDetachedObjectDereferenceResult dereferenced = await checkedDereference(
                                current.Reference, checkedContext, pool, cancellationToken).ConfigureAwait(false);

                            if(dereferenced is not JAdESDetachedObjectDereferenceSuccess success)
                            {
                                string reason = dereferenced is JAdESDetachedObjectDereferenceFailure failure
                                    ? failure.Reason
                                    : "the dereference delegate returned neither a success nor a failure result.";

                                throw new JAdESDetachedObjectDereferenceException(current.Reference, reason);
                            }

                            using(success.Content)
                            {
                                DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                                    success.Content.AsReadOnlyMemory(), outputByteLength, digestTag, pool,
                                    cancellationToken: cancellationToken).ConfigureAwait(false);

                                entries.Add(new JAdESReferencedDataObject(current.Reference, current.ContentType, digest));
                            }
                        }

                        var reference = new JAdESObjectIdByUriHashReference(objectIdByUriHash.HashAlgorithm, entries);

                        //JA-5.2.8.3.3-05: the JWS Payload contributes as an empty stream to the JWS Signature
                        //Value computation under this mechanism -- no rented Signing-Input buffer to dispose.
                        return new PayloadResolution(reference, ReadOnlyMemory<byte>.Empty, null);
                    }
                    catch
                    {
                        for(int i = 0; i < entries.Count; ++i)
                        {
                            entries[i].Dispose();
                        }

                        throw;
                    }
                }

            case JAdESDetachedUnknownMechanismPayloadInput unknown:
                {
                    if(unknownHandler is null)
                    {
                        throw new NotSupportedException(
                            $"sigD.mId '{unknown.MechanismIdentifier}' is neither ObjectIdByURI, " +
                            "ObjectIdByURIHash, nor HttpHeaders, and no unknown-mechanism handler was supplied " +
                            "(ETSI TS 119 182-1 V1.2.1, clause 5.2.8.1, JA-5.2.8.1-C1).");
                    }

                    RequireContext(context, "the unknown-mechanism handler", out JAdESDetachedObjectDereferenceContext checkedUnknownContext);

                    var entries = new List<JAdESReferencedDataObject>(unknown.References.Count);
                    for(int i = 0; i < unknown.References.Count; ++i)
                    {
                        entries.Add(new JAdESReferencedDataObject(unknown.References[i].Reference, unknown.References[i].ContentType));
                    }

                    var reference = new JAdESUnknownDetachedDataObjectReference(unknown.MechanismIdentifier, entries, unknown.HashAlgorithm);
                    PooledMemory payload = await unknownHandler(
                        unknown.MechanismIdentifier, unknown.References, unknown.HashAlgorithm, checkedUnknownContext, pool, cancellationToken).ConfigureAwait(false);

                    return new PayloadResolution(reference, payload.AsReadOnlyMemory(), payload);
                }

            default:
                throw new NotSupportedException($"Unrecognized {nameof(JAdESSigningPayloadInput)} kind '{input.GetType().Name}'.");
        }
    }


    /// <summary>
    /// Validates that both a dereference delegate and its context are non-null, throwing
    /// <see cref="ArgumentException"/> naming <paramref name="mechanismName"/> otherwise, and hands back the
    /// checked non-null references for the caller to use directly.
    /// </summary>
    private static void RequireDereference(
        JAdESDetachedObjectDereferenceDelegate? dereferenceDelegate,
        JAdESDetachedObjectDereferenceContext? context,
        string mechanismName,
        out JAdESDetachedObjectDereferenceDelegate checkedDereferenceDelegate,
        out JAdESDetachedObjectDereferenceContext checkedContext)
    {
        if(dereferenceDelegate is null)
        {
            throw new ArgumentException($"The {mechanismName} mechanism requires a non-null dereference delegate.", nameof(dereferenceDelegate));
        }

        RequireContext(context, mechanismName, out checkedContext);
        checkedDereferenceDelegate = dereferenceDelegate;
    }


    /// <summary>Validates that <paramref name="context"/> is non-null, throwing <see cref="ArgumentException"/> naming <paramref name="mechanismName"/> otherwise, and hands back the checked non-null reference.</summary>
    private static void RequireContext(
        JAdESDetachedObjectDereferenceContext? context,
        string mechanismName,
        out JAdESDetachedObjectDereferenceContext checkedContext)
    {
        if(context is null)
        {
            throw new ArgumentException($"The {mechanismName} mechanism requires a non-null dereference context.", nameof(context));
        }

        checkedContext = context;
    }


    /// <summary>
    /// Resolves the <see cref="Tag"/> and output byte length the registered digest delegate needs for
    /// <paramref name="hashAlgorithm"/> — only SHA-256/384/512 resolve. Internal so
    /// <see cref="JAdESSignatureValidation"/>'s own <c>ObjectIdByURIHash</c> digest re-verification reuses this
    /// EXACT resolution rather than duplicating it (reuse over reinvention).
    /// </summary>
    /// <exception cref="NotSupportedException"><paramref name="hashAlgorithm"/> is not SHA-256/384/512.</exception>
    internal static (Tag DigestTag, int OutputByteLength) ResolveDigestParameters(string hashAlgorithm)
    {
        if(WellKnownHashAlgorithms.IsSha256(hashAlgorithm))
        {
            return (CryptoTags.Sha256Digest, 32);
        }

        if(WellKnownHashAlgorithms.IsSha384(hashAlgorithm))
        {
            return (CryptoTags.Sha384Digest, 48);
        }

        if(WellKnownHashAlgorithms.IsSha512(hashAlgorithm))
        {
            return (CryptoTags.Sha512Digest, 64);
        }

        throw new NotSupportedException(
            $"Digest algorithm '{hashAlgorithm}' is not supported for sigD hashV computation (ETSI TS 119 182-1 " +
            "V1.2.1, clause 5.2.8.1, JA-5.2.8.1-19 -- only SHA-256/384/512 resolve through the registered digest delegate).");
    }


    /// <summary>Returns a new <see cref="JAdESProtectedHeaders"/> sharing every unchanged member of <paramref name="headers"/> by reference, with <see cref="JAdESProtectedHeaders.SigD"/> completed and <c>"sigD"</c> merged into <see cref="JAdESProtectedHeaders.CriticalLabels"/> (JA-5.1.9-04/-05).</summary>
    private static JAdESProtectedHeaders CompleteHeaders(JAdESProtectedHeaders headers, JAdESDetachedDataObjectReference sigD)
    {
        return new JAdESProtectedHeaders(
            headers.Algorithm,
            headers.ContentType,
            headers.KeyId,
            headers.X5U,
            headers.X5tHashS256,
            headers.X5Chain,
            MergeCriticalLabel(headers.CriticalLabels, WellKnownJAdESHeaderNames.SigD),
            headers.B64,
            headers.IssuedAt,
            headers.SigT,
            headers.X5tHashO,
            headers.SigX5ts,
            headers.SignerCommitments,
            headers.SignatureProductionPlace,
            headers.SignerAttributes,
            headers.PayloadTimestamps,
            headers.SignaturePolicyIdentifier,
            sigD);
    }


    /// <summary>Returns <paramref name="existing"/> with <paramref name="label"/> appended, unless already present.</summary>
    private static List<string> MergeCriticalLabel(IReadOnlyList<string>? existing, string label)
    {
        var merged = existing is null ? new List<string>() : new List<string>(existing);

        for(int i = 0; i < merged.Count; ++i)
        {
            if(WellKnownJAdESHeaderNames.Equals(merged[i], label))
            {
                return merged;
            }
        }

        merged.Add(label);

        return merged;
    }
}
