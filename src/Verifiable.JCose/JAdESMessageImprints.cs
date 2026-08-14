using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The three-way source union for the payload contribution of a JAdES <c>arcTst</c> message-imprint input
/// (clause 5.3.6.2.3, steps 1-2), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// Every arm carries its contribution as already-final wire bytes — this builder is a pure concatenator (it
/// never encodes, never dereferences, never canonicalizes a payload; see
/// <see cref="JAdESMessageImprints"/>'s own class remarks). The caller resolves which arm applies from the
/// signed <c>b64</c>/<c>sigD</c> header parameters it already holds, exactly as it resolves
/// <see cref="JAdESDetachedDataObjectReference"/>'s own dereference seam (clause 5.2.8.3.1) before calling
/// here.
/// </para>
/// </remarks>
public abstract class JAdESArchiveTimestampPayloadSource
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected JAdESArchiveTimestampPayloadSource()
    {
    }
}


/// <summary>
/// The <c>sigD</c>-absent, <c>b64</c>=<see langword="false"/> arm of <see cref="JAdESArchiveTimestampPayloadSource"/>
/// (JA-5.3.6.2.3-02): "concatenate the JWS Payload value" — the raw payload bytes, unencoded.
/// </summary>
[DebuggerDisplay("JAdESRawPayloadImprintSource: {PayloadBytes.Length} bytes")]
public sealed class JAdESRawPayloadImprintSource : JAdESArchiveTimestampPayloadSource
{
    /// <summary>Initializes a new <see cref="JAdESRawPayloadImprintSource"/>.</summary>
    /// <param name="payloadBytes">The raw JWS Payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</param>
    public JAdESRawPayloadImprintSource(ReadOnlyMemory<byte> payloadBytes)
    {
        PayloadBytes = payloadBytes;
    }

    /// <summary>The raw JWS Payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</summary>
    public ReadOnlyMemory<byte> PayloadBytes { get; }
}


/// <summary>
/// The <c>sigD</c>-absent, <c>b64</c>=<see langword="true"/>-or-absent arm of
/// <see cref="JAdESArchiveTimestampPayloadSource"/> (JA-5.3.6.2.3-03): "concatenate the base64url-encoded JWS
/// Payload" — the payload's own base64url wire TEXT, i.e. the literal middle segment of the JWS compact
/// serialization, byte-exact.
/// </summary>
[DebuggerDisplay("JAdESBase64UrlPayloadImprintSource: {Base64UrlPayloadText.Length} bytes")]
public sealed class JAdESBase64UrlPayloadImprintSource : JAdESArchiveTimestampPayloadSource
{
    /// <summary>Initializes a new <see cref="JAdESBase64UrlPayloadImprintSource"/>.</summary>
    /// <param name="base64UrlPayloadText">
    /// The base64url-encoded JWS Payload's wire text. <strong>Borrowed</strong> view — the caller owns the
    /// underlying memory.
    /// </param>
    public JAdESBase64UrlPayloadImprintSource(ReadOnlyMemory<byte> base64UrlPayloadText)
    {
        Base64UrlPayloadText = base64UrlPayloadText;
    }

    /// <summary>
    /// The base64url-encoded JWS Payload's wire text. <strong>Borrowed</strong> view — the caller owns the
    /// underlying memory.
    /// </summary>
    public ReadOnlyMemory<byte> Base64UrlPayloadText { get; }
}


/// <summary>
/// The <c>sigD</c>-present arm of <see cref="JAdESArchiveTimestampPayloadSource"/> (JA-5.3.6.2.3-04/-05/-06):
/// the bytes already produced by processing <c>sigD</c>'s <c>pars</c> member — either the in-library
/// <c>HttpHeaders</c> canonicalization (clause 5.2.8.2, no seam) or the
/// <c>ObjectIdByURI</c>/<c>ObjectIdByURIHash</c> dereference seam (clause 5.2.8.3.1) — regardless of which
/// mechanism produced them.
/// </summary>
/// <remarks>
/// JA-5.3.6.2.3-05: for the <c>HttpHeaders</c> mechanism, the <c>"Digest"</c> pseudo-header's own processing
/// is "retrieving the bytes of the body of the HTTP message" — one more caller-resolved fact folded into
/// <see cref="ProcessedBytes"/> alongside every other <c>pars</c> element, not a separate parameter here.
/// </remarks>
[DebuggerDisplay("JAdESSigDProcessedPayloadImprintSource: {ProcessedBytes.Length} bytes")]
public sealed class JAdESSigDProcessedPayloadImprintSource : JAdESArchiveTimestampPayloadSource
{
    /// <summary>Initializes a new <see cref="JAdESSigDProcessedPayloadImprintSource"/>.</summary>
    /// <param name="processedBytes">
    /// The ordered, already-processed bytes to concatenate. <strong>Borrowed</strong> view — the caller owns the
    /// underlying memory.
    /// </param>
    public JAdESSigDProcessedPayloadImprintSource(ReadOnlyMemory<byte> processedBytes)
    {
        ProcessedBytes = processedBytes;
    }

    /// <summary>
    /// The ordered, already-processed bytes to concatenate. <strong>Borrowed</strong> view — the caller owns the
    /// underlying memory.
    /// </summary>
    public ReadOnlyMemory<byte> ProcessedBytes { get; }
}


/// <summary>
/// The explicit, per-call parameter set for the <c>arcTst</c> message-imprint input builder (clause 5.3.6.2.3
/// steps 1-6, shared verbatim by clause 5.3.6.2.4 per JA-5.3.6.2.4-01). No closure capture: every input the
/// algorithm needs travels through this value, never through a captured outer variable.
/// </summary>
/// <remarks>
/// <see cref="CanonAlg"/>/<see cref="Canonicalize"/> are consulted only when the <see cref="JAdESUnsignedHeaders"/>
/// passed to <see cref="JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync"/>/
/// <see cref="JAdESMessageImprints.BuildArchiveTimestampValidationMessageImprintInputAsync"/> reports
/// <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> — see that class's remarks for why the mode switch is
/// read from the container rather than from a second caller-supplied selector. At validation time,
/// <see cref="CanonAlg"/> is additionally verified against the <c>arcTst</c> element under validation's own
/// declared <c>canonAlg</c> (structural-linkage discipline) — a typed fault on mismatch, not a
/// silently-trusted free parameter.
/// </remarks>
public readonly record struct JAdESArchiveTimestampImprintContext
{
    /// <summary>Gets the payload contribution for steps 1/2 — always contributes exactly one segment.</summary>
    public required JAdESArchiveTimestampPayloadSource PayloadSource { get; init; }

    /// <summary>
    /// Gets the JWS Protected Header's own base64url wire text for step 4 (JA-5.3.6.2.3-08) — the literal
    /// wire segment, byte-exact, never a re-derived encoding of the decoded header model (mirrors
    /// <see cref="CryptoTags.JoseEncodedProtectedHeader"/>'s own rationale).
    /// </summary>
    public required ReadOnlyMemory<byte> ProtectedHeaderBase64Url { get; init; }

    /// <summary>
    /// Gets the JAdES Signature Value's own base64url wire text for step 5 (JA-5.3.6.2.3-09) — the literal
    /// wire segment, byte-exact.
    /// </summary>
    public required ReadOnlyMemory<byte> SignatureValueBase64Url { get; init; }

    /// <summary>
    /// Gets the canonicalization-algorithm identifier this specific <c>arcTst</c> instance declares (or, at
    /// validation time, the one the instance under validation already declares) — required exactly when the
    /// enclosing <see cref="JAdESUnsignedHeaders"/> reports <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>
    /// (JA-5.4.3.3-16/-17), and rejected (JA-5.3.1-15, fail-closed) when the
    /// container reports <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>. <see langword="null"/> under
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, where no canonicalization algorithm applies at all
    /// (JA-5.4.3.3-18: canonAlg-absent means the original wire bytes of each time-stamped component).
    /// </summary>
    public string? CanonAlg { get; init; }

    /// <summary>
    /// Gets the registered canonicalization delegate — required exactly when <see cref="CanonAlg"/> is
    /// required. See <see cref="JAdESCanonicalizeUnsignedElementDelegate"/> for the seam this class never
    /// implements in-library (this library's serialization firewall).
    /// </summary>
    public JAdESCanonicalizeUnsignedElementDelegate? Canonicalize { get; init; }
}


/// <summary>
/// Canonicalizes one clear-JSON <c>etsiU</c> array element under a declared <c>canonAlg</c> identifier
/// (clause 5.3.6.2.4 step 7b/7c, Annex A.1.5.1.3-04/A.1.5.2.3-02), producing the canonical octet stream a
/// message-imprint builder concatenates. Registered-delegate seam, mirroring the
/// <see cref="Verifiable.Cryptography.ComputeDigestDelegate"/> precedent: no canonicalization algorithm ships
/// in-library — canonicalizing a JSON value needs a JSON serializer, which the serialization
/// firewall keeps out of <c>Verifiable.Cryptography</c>/<c>Verifiable.JCose</c>
/// entirely; a caller supplies the concrete implementation (its natural home is <c>Verifiable.Json</c>, reached
/// through this delegate, never through a project reference this library would otherwise need).
/// </summary>
/// <param name="canonAlg">The declared canonicalization-algorithm identifier.</param>
/// <param name="element">
/// The clear-JSON <c>etsiU</c> element to canonicalize — its <see cref="JAdESUnsignedHeaderElement.Kind"/>
/// plus whatever concrete arm's own decoded value or, for the mode-agnostic <c>cSig</c>/unknown arms, raw wire
/// text it carries. The full element is passed rather than a pre-extracted value because the sixteen named arms
/// carry as many different decoded shapes and the implementation, not this seam, owns dispatching on them.
/// </param>
/// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
/// <param name="cancellationToken">A token to observe while canonicalizing.</param>
/// <returns>The canonicalized octet stream, pool-rented; the caller owns and disposes it.</returns>
public delegate ValueTask<PooledMemory> JAdESCanonicalizeUnsignedElementDelegate(
    string canonAlg,
    JAdESUnsignedHeaderElement element,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// The JAdES message-imprint-INPUT builders — pure byte-assembly functions that produce the bytes a
/// time-stamp-token request hashes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clauses 5.3.6.2.2-5.3.6.2.4 (<c>arcTst</c>) and Annex A.1.5.1.1-A.1.5.2.3
/// (<c>sigRTst</c>/<c>rfsTst</c>). The JAdES-side counterpart of <c>CBAdESMessageImprints</c> (<c>Verifiable.Cbor</c>);
/// see this class's own remarks for where JAdES's own text diverges from that shape exemplar.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope.</strong> These builders assemble bytes; they never hash them (digest computation happens at
/// TSA-request time, via the registered <see cref="Verifiable.Cryptography.ComputeDigestDelegate"/>, a later
/// stage's concern) and they never perform I/O or JSON serialization of their own — every input arrives
/// already resolved to bytes (<see cref="JAdESArchiveTimestampPayloadSource"/>'s three arms) or reaches
/// canonical bytes through the registered <see cref="JAdESCanonicalizeUnsignedElementDelegate"/> seam.
/// </para>
/// <para>
/// <strong>No untrusted-byte parsing, so no <c>Try</c>-style surface.</strong> Unlike
/// <c>CBAdESMessageImprints</c> (<c>Verifiable.Cbor</c>), which walks raw, potentially malformed CBOR bytes and
/// therefore exposes a fail-closed <c>TryBuild*</c> shape, every builder here walks an already-constructed,
/// already-validated <see cref="JAdESUnsignedHeaders"/> — there is no wire-parsing failure mode to report.
/// This mirrors <c>CBAdESMessageImprints</c> (<c>Verifiable.Cbor</c>)'s own reasoning for its two non-<c>Try</c>
/// methods ("the two builders that never parse CBOR at all... have no failure mode to report and are plain,
/// non-<c>Try</c> methods") extended to every builder in this class, since none of them parses untrusted bytes
/// either.
/// </para>
/// <para>
/// <strong>The mode switch is read from the container, not from a second caller-supplied selector.</strong>
/// JAdES's <c>etsiU</c> array is homogeneous by construction ("the
/// duality is a WHOLE-ARRAY fact, never a per-element one" — enforced by <see cref="JAdESUnsignedHeaders"/>
/// itself). Consequently every builder below dispatches internally on <see cref="JAdESUnsignedHeaders.Mode"/>
/// to choose between clause 5.3.6.2.3 (Base64url incorporation) and clause 5.3.6.2.4 (clear JSON
/// incorporation) rather than exposing two same-shaped public overloads a caller would have to pick between —
/// which would only reopen the mixed-mode risk this design closes. Under Base64url incorporation, a caller-supplied
/// <c>canonAlg</c>/canonicalize delegate is a typed, fail-closed REJECTION (JA-5.3.1-15) — never a
/// silently-ignored no-op.
/// </para>
/// <para>
/// <strong>arcTst's payload-then-header-then-signature-then-etsiU order.</strong> JA-5.3.6.2.3-02..-11: the
/// assembled input is <c>[payload contribution] . [protected header, base64url] . [signature value,
/// base64url] . [etsiU contribution]</c> — note this is NOT the header-payload-signature order of a JWS
/// compact serialization; it is the order the numbered steps literally give, reproduced here unchanged.
/// </para>
/// <para>
/// <strong>No absent-vs-empty sentinel, unlike CB-AdES's own CBOR-array accumulator design.</strong> JAdES's <c>etsiU</c> concatenation
/// (steps 7/7a/7b/7c) is a plain sequential concatenation with no enclosing array/placeholder structure, so an
/// empty element sequence (the validation-time prefix of the very first <c>etsiU</c> element, or an empty
/// <c>sigRTst</c>/<c>rfsTst</c> filter result) simply contributes zero bytes — there is no CBOR-array "slot"
/// requiring a zero-length sentinel the way <c>CBAdESMessageImprints</c> (<c>Verifiable.Cbor</c>)'s own
/// accumulator-array design needs one. <see cref="JAdESUnsignedHeaders"/> itself is always non-empty
/// (JA-5.3.1-07), so this only arises for a genuinely empty PREFIX or FILTER result, never for an absent
/// container.
/// </para>
/// <para>
/// <strong><c>sigRTst</c>/<c>rfsTst</c> are PREFIX-BOUND, the CB-AdES analog.</strong>
/// Annex A.1.5.1.2-04/A.1.5.1.3-04/A.1.5.2.2-02/A.1.5.2.3-02 give no positional text on their own, but Table 1's
/// NOTE 7 ("Several instances of this component can be incorporated into the JAdES signature, coming from
/// different TSAs" — <c>sigTst</c>) is the exact analogue of the CB-AdES Table 14 note this reasoning
/// draws from, and JA-5.3.1-03 (append-at-end) makes post-<c>sigRTst</c> appends legal. The ruled reading: the
/// message-imprint input for a SPECIFIC <c>sigRTst</c>/<c>rfsTst</c> instance — at generation and validation
/// alike — is built from only the <c>etsiU</c> elements that PRECEDE that instance's own position, the identical
/// discipline <see cref="BuildArchiveTimestampGenerationMessageImprintInputAsync"/>/
/// <see cref="BuildArchiveTimestampValidationMessageImprintInputAsync"/> already apply to <c>arcTst</c>:
/// generation passes the current element count (the pre-append position — every element trivially precedes an
/// instance not yet incorporated), validation passes the instance's own index, and validation additionally
/// asserts the element at that index IS the expected arm and, under clear mode, that the supplied
/// <c>canonAlg</c> equals that element's own declared <c>canonAlg</c> (a typed fault otherwise) — the same
/// structural-linkage discipline <see cref="BuildArchiveTimestampValidationMessageImprintInputAsync"/> applies.
/// </para>
/// </remarks>
public static class JAdESMessageImprints
{
    /// <summary>The ASCII '.' separator byte JA-5.3.6.2.3-07/-10 and Annex A.1.5.1.2-03 concatenate literally.</summary>
    private const byte Dot = (byte)'.';


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint input in generation mode: every current element of
    /// <paramref name="etsiU"/> contributes (JA-5.3.6.2.3-11/JA-5.3.6.2.4-02 — the new <c>arcTst</c> is not yet
    /// incorporated, so "every element" and "every element that precedes the new one" coincide).
    /// </summary>
    /// <param name="context">The algorithm's explicit inputs (steps 1-6).</param>
    /// <param name="etsiU">The signature's current <c>etsiU</c> container.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="cancellationToken">A token to observe while canonicalizing (clear-JSON mode only).</param>
    /// <returns>The message-imprint input, pool-rented; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">
    /// <see cref="JAdESArchiveTimestampImprintContext.PayloadSource"/>, <paramref name="etsiU"/>, or
    /// <paramref name="pool"/> is <see langword="null"/>; or <paramref name="etsiU"/> reports
    /// <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> and <see cref="JAdESArchiveTimestampImprintContext.Canonicalize"/>
    /// is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="etsiU"/> reports <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> and
    /// <see cref="JAdESArchiveTimestampImprintContext.CanonAlg"/> is <see langword="null"/> or empty; or
    /// <paramref name="etsiU"/> reports <see cref="JAdESEtsiUIncorporationMode.Base64Url"/> and a
    /// <c>canonAlg</c>/canonicalize delegate is supplied anyway (JA-5.3.1-15, fail-closed).
    /// </exception>
    public static ValueTask<PooledMemory> BuildArchiveTimestampGenerationMessageImprintInputAsync(
        JAdESArchiveTimestampImprintContext context,
        JAdESUnsignedHeaders etsiU,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        BuildArchiveTimestampMessageImprintInputCoreAsync(context, etsiU, arcTstElementIndex: null, pool, cancellationToken);


    /// <summary>
    /// Builds the <c>arcTst</c> message-imprint input in validation mode: only the <paramref name="etsiU"/>
    /// elements strictly before the <c>arcTst</c> under validation contribute (JA-5.3.6.2.3-12/-13,
    /// JA-5.3.6.2.4-03/-04).
    /// </summary>
    /// <param name="context">The algorithm's explicit inputs (steps 1-6).</param>
    /// <param name="etsiU">The signature's <c>etsiU</c> container, as validated (including the <c>arcTst</c> under validation).</param>
    /// <param name="arcTstElementIndex">
    /// The zero-based position of the <c>arcTst</c> element under validation, within <paramref name="etsiU"/>.
    /// Elements at positions <c>0</c> through <c>arcTstElementIndex - 1</c> contribute — matches
    /// <see cref="JAdESUnsignedHeaders.ElementsBefore(int)"/>'s own exclusive-upper-bound convention.
    /// </param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="cancellationToken">A token to observe while canonicalizing (clear-JSON mode only).</param>
    /// <returns>The message-imprint input, pool-rented; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">
    /// <see cref="JAdESArchiveTimestampImprintContext.PayloadSource"/>, <paramref name="etsiU"/>, or
    /// <paramref name="pool"/> is <see langword="null"/>; or the clear-JSON canonicalize precondition
    /// (see <see cref="BuildArchiveTimestampGenerationMessageImprintInputAsync"/>) is unmet.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="arcTstElementIndex"/> is negative or does not identify an existing element of
    /// <paramref name="etsiU"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// The clear-JSON canonAlg precondition is unmet (see
    /// <see cref="BuildArchiveTimestampGenerationMessageImprintInputAsync"/>); the element at
    /// <paramref name="arcTstElementIndex"/> is not an <c>arcTst</c> instance (typed fault); or, under
    /// clear mode, <see cref="JAdESArchiveTimestampImprintContext.CanonAlg"/> does not equal that element's own
    /// declared <c>canonAlg</c> (structural linkage).
    /// </exception>
    public static ValueTask<PooledMemory> BuildArchiveTimestampValidationMessageImprintInputAsync(
        JAdESArchiveTimestampImprintContext context,
        JAdESUnsignedHeaders etsiU,
        int arcTstElementIndex,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        BuildArchiveTimestampMessageImprintInputCoreAsync(context, etsiU, arcTstElementIndex, pool, cancellationToken);


    /// <summary>
    /// The shared core behind <see cref="BuildArchiveTimestampGenerationMessageImprintInputAsync"/> and
    /// <see cref="BuildArchiveTimestampValidationMessageImprintInputAsync"/> — JA-5.3.6.2.3 steps 1-6 (shared
    /// verbatim with clause 5.3.6.2.4 per JA-5.3.6.2.4-01), followed by the mode-dispatched <c>etsiU</c>
    /// contribution (step 7/7a Base64url, or step 7b/7c clear-JSON).
    /// </summary>
    private static async ValueTask<PooledMemory> BuildArchiveTimestampMessageImprintInputCoreAsync(
        JAdESArchiveTimestampImprintContext context,
        JAdESUnsignedHeaders etsiU,
        int? arcTstElementIndex,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context.PayloadSource);
        ArgumentNullException.ThrowIfNull(etsiU);
        ArgumentNullException.ThrowIfNull(pool);
        ValidateCanonicalizationArguments(etsiU.Mode, context.CanonAlg, context.Canonicalize);

        int sliceBound = etsiU.Count;
        if(arcTstElementIndex.HasValue)
        {
            int index = arcTstElementIndex.Value;
            if(index < 0 || index >= etsiU.Count)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(arcTstElementIndex),
                    index,
                    "The arcTst under validation must identify an existing etsiU element (ETSI TS 119 182-1 V1.2.1, clause 5.3.6.2.3 step 7a / 5.3.6.2.4 step 7c).");
            }

            if(etsiU[index] is not JAdESUnsignedHeaderElementArchiveTimestamp archiveTimestamp)
            {
                throw new ArgumentException(
                    $"The etsiU element under validation must be an arcTst instance; found '{etsiU[index].Kind}' (ETSI TS 119 182-1 V1.2.1, clause 5.3.6.2.1).",
                    nameof(arcTstElementIndex));
            }

            if(etsiU.Mode == JAdESEtsiUIncorporationMode.ClearJson
                && archiveTimestamp.Carriage is JAdESClearUnsignedValue<AdESTimestampContainer> clear
                && !string.Equals(context.CanonAlg, clear.Value.CanonAlg, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The supplied canonAlg must equal the arcTst element's own declared canonAlg (structural linkage; ETSI TS 119 182-1 V1.2.1, clause 5.3.1, JA-5.3.1-14).",
                    nameof(context));
            }

            sliceBound = index;
        }

        IReadOnlyList<JAdESUnsignedHeaderElement> elements = etsiU.ElementsBefore(sliceBound);

        ReadOnlyMemory<byte> payloadContribution = GetPayloadContribution(context.PayloadSource);

        using PooledMemory etsiUContribution = await GetEtsiUContributionAsync().ConfigureAwait(false);

        int totalLength = payloadContribution.Length + 1
            + context.ProtectedHeaderBase64Url.Length + 1
            + context.SignatureValueBase64Url.Length + 1
            + etsiUContribution.Length;

        IMemoryOwner<byte> storage = pool.Rent(Math.Max(totalLength, 1));
        try
        {
            Span<byte> destination = storage.Memory.Span;
            int offset = 0;
            payloadContribution.Span.CopyTo(destination[offset..]);
            offset += payloadContribution.Length;
            destination[offset++] = Dot;
            context.ProtectedHeaderBase64Url.Span.CopyTo(destination[offset..]);
            offset += context.ProtectedHeaderBase64Url.Length;
            destination[offset++] = Dot;
            context.SignatureValueBase64Url.Span.CopyTo(destination[offset..]);
            offset += context.SignatureValueBase64Url.Length;
            destination[offset++] = Dot;
            etsiUContribution.AsReadOnlySpan().CopyTo(destination[offset..]);

            return new PooledMemory(storage, totalLength, CryptoTags.JAdESMessageImprintInput);
        }
        catch
        {
            storage.Dispose();
            throw;
        }

        async ValueTask<PooledMemory> GetEtsiUContributionAsync() =>
            etsiU.Mode == JAdESEtsiUIncorporationMode.Base64Url
                ? ConcatenateOpaqueElements(elements, pool)
                : await ConcatenateCanonicalizedElementsAsync(elements, context.CanonAlg!, context.Canonicalize!, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the <c>sigRTst</c> message-imprint input in generation mode (Annex A.1.5.1.2/A.1.5.1.3): every
    /// current element of <paramref name="etsiU"/> that qualifies (generation and the not-yet-incorporated
    /// instance's own prefix coincide, the <c>arcTst</c>-generation analog).
    /// </summary>
    /// <param name="signatureValueBase64Url">The JAdES Signature Value's own base64url wire text (step 1).</param>
    /// <param name="etsiU">The signature's current <c>etsiU</c> container.</param>
    /// <param name="canonAlg">
    /// The canonicalization-algorithm identifier this <c>sigRTst</c> instance declares — required exactly when
    /// <paramref name="etsiU"/> reports <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>.
    /// </param>
    /// <param name="canonicalize">The registered canonicalization delegate — required exactly when <paramref name="canonAlg"/> is required.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="cancellationToken">A token to observe while canonicalizing (clear-JSON mode only).</param>
    /// <returns>The message-imprint input, pool-rented; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="etsiU"/> or <paramref name="pool"/> is <see langword="null"/>; or the clear-JSON
    /// canonicalize precondition is unmet.
    /// </exception>
    /// <exception cref="ArgumentException">The clear-JSON canonAlg precondition is unmet, or a canonAlg/delegate is supplied under Base64url mode (JA-5.3.1-15).</exception>
    public static ValueTask<PooledMemory> BuildSignatureAndReferencesTimestampGenerationMessageImprintInputAsync(
        ReadOnlyMemory<byte> signatureValueBase64Url,
        JAdESUnsignedHeaders etsiU,
        string? canonAlg,
        JAdESCanonicalizeUnsignedElementDelegate? canonicalize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        BuildReferencesFamilyMessageImprintInputCoreAsync(includeSignatureValue: true, signatureValueBase64Url, etsiU, ownElementIndex: null, canonAlg, canonicalize, pool, cancellationToken);


    /// <summary>
    /// Builds the <c>sigRTst</c> message-imprint input in validation mode (the <c>arcTst</c>-validation
    /// analog): only the <paramref name="etsiU"/> elements strictly before the <c>sigRTst</c> under validation,
    /// among the five qualifying kinds, contribute.
    /// </summary>
    /// <param name="signatureValueBase64Url">The JAdES Signature Value's own base64url wire text (step 1).</param>
    /// <param name="etsiU">The signature's <c>etsiU</c> container, as validated (including the <c>sigRTst</c> under validation).</param>
    /// <param name="sigRTstElementIndex">The zero-based position of the <c>sigRTst</c> element under validation, within <paramref name="etsiU"/>.</param>
    /// <param name="canonAlg">The canonicalization-algorithm identifier — required exactly under clear-JSON incorporation.</param>
    /// <param name="canonicalize">The registered canonicalization delegate — required exactly when <paramref name="canonAlg"/> is required.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="cancellationToken">A token to observe while canonicalizing (clear-JSON mode only).</param>
    /// <returns>The message-imprint input, pool-rented; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="etsiU"/> or <paramref name="pool"/> is <see langword="null"/>; or the clear-JSON canonicalize precondition is unmet.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sigRTstElementIndex"/> does not identify an existing element of <paramref name="etsiU"/>.</exception>
    /// <exception cref="ArgumentException">
    /// The clear-JSON canonAlg precondition is unmet; the element at <paramref name="sigRTstElementIndex"/> is
    /// not a <c>sigRTst</c> instance (typed fault); or, under clear mode, <paramref name="canonAlg"/> does not
    /// equal that element's own declared <c>canonAlg</c> (structural linkage).
    /// </exception>
    public static ValueTask<PooledMemory> BuildSignatureAndReferencesTimestampValidationMessageImprintInputAsync(
        ReadOnlyMemory<byte> signatureValueBase64Url,
        JAdESUnsignedHeaders etsiU,
        int sigRTstElementIndex,
        string? canonAlg,
        JAdESCanonicalizeUnsignedElementDelegate? canonicalize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        BuildReferencesFamilyMessageImprintInputCoreAsync(includeSignatureValue: true, signatureValueBase64Url, etsiU, ownElementIndex: sigRTstElementIndex, canonAlg, canonicalize, pool, cancellationToken);


    /// <summary>
    /// Builds the <c>rfsTst</c> message-imprint input in generation mode (Annex A.1.5.2.2/A.1.5.2.3): identical
    /// to <see cref="BuildSignatureAndReferencesTimestampGenerationMessageImprintInputAsync"/> minus the leading
    /// signature value and its separator — <c>rfsTst</c> filters over <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/
    /// <c>arRefs</c> only (no <c>sigTst</c>).
    /// </summary>
    /// <param name="etsiU">The signature's current <c>etsiU</c> container.</param>
    /// <param name="canonAlg">The canonicalization-algorithm identifier this <c>rfsTst</c> instance declares — required exactly under clear-JSON incorporation.</param>
    /// <param name="canonicalize">The registered canonicalization delegate — required exactly when <paramref name="canonAlg"/> is required.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="cancellationToken">A token to observe while canonicalizing (clear-JSON mode only).</param>
    /// <returns>The message-imprint input, pool-rented; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="etsiU"/> or <paramref name="pool"/> is <see langword="null"/>; or the clear-JSON canonicalize precondition is unmet.</exception>
    /// <exception cref="ArgumentException">The clear-JSON canonAlg precondition is unmet, or a canonAlg/delegate is supplied under Base64url mode (JA-5.3.1-15).</exception>
    public static ValueTask<PooledMemory> BuildReferencesOnlyTimestampGenerationMessageImprintInputAsync(
        JAdESUnsignedHeaders etsiU,
        string? canonAlg,
        JAdESCanonicalizeUnsignedElementDelegate? canonicalize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        BuildReferencesFamilyMessageImprintInputCoreAsync(includeSignatureValue: false, default, etsiU, ownElementIndex: null, canonAlg, canonicalize, pool, cancellationToken);


    /// <summary>
    /// Builds the <c>rfsTst</c> message-imprint input in validation mode (the <c>arcTst</c>-validation
    /// analog): only the <paramref name="etsiU"/> elements strictly before the <c>rfsTst</c> under validation,
    /// among the four qualifying kinds, contribute.
    /// </summary>
    /// <param name="etsiU">The signature's <c>etsiU</c> container, as validated (including the <c>rfsTst</c> under validation).</param>
    /// <param name="rfsTstElementIndex">The zero-based position of the <c>rfsTst</c> element under validation, within <paramref name="etsiU"/>.</param>
    /// <param name="canonAlg">The canonicalization-algorithm identifier — required exactly under clear-JSON incorporation.</param>
    /// <param name="canonicalize">The registered canonicalization delegate — required exactly when <paramref name="canonAlg"/> is required.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer is rented from.</param>
    /// <param name="cancellationToken">A token to observe while canonicalizing (clear-JSON mode only).</param>
    /// <returns>The message-imprint input, pool-rented; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="etsiU"/> or <paramref name="pool"/> is <see langword="null"/>; or the clear-JSON canonicalize precondition is unmet.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="rfsTstElementIndex"/> does not identify an existing element of <paramref name="etsiU"/>.</exception>
    /// <exception cref="ArgumentException">
    /// The clear-JSON canonAlg precondition is unmet; the element at <paramref name="rfsTstElementIndex"/> is
    /// not a <c>rfsTst</c> instance (typed fault); or, under clear mode, <paramref name="canonAlg"/> does not
    /// equal that element's own declared <c>canonAlg</c> (structural linkage).
    /// </exception>
    public static ValueTask<PooledMemory> BuildReferencesOnlyTimestampValidationMessageImprintInputAsync(
        JAdESUnsignedHeaders etsiU,
        int rfsTstElementIndex,
        string? canonAlg,
        JAdESCanonicalizeUnsignedElementDelegate? canonicalize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default) =>
        BuildReferencesFamilyMessageImprintInputCoreAsync(includeSignatureValue: false, default, etsiU, ownElementIndex: rfsTstElementIndex, canonAlg, canonicalize, pool, cancellationToken);


    /// <summary>
    /// The shared core behind the <c>sigRTst</c>/<c>rfsTst</c> generation/validation builders — Annex
    /// A.1.5.1.2/1.3 and A.1.5.2.2/2.3 are identical except for the leading signature-value segment (mirrors
    /// <c>CBAdESMessageImprints</c> (<c>Verifiable.Cbor</c>)'s own include-signature-value core parameter for
    /// the structurally identical CB-AdES pair), and this prefix-bound discipline mirrors
    /// <see cref="BuildArchiveTimestampMessageImprintInputCoreAsync"/>'s own <c>etsiUSliceBound</c>/structural
    /// checks exactly.
    /// </summary>
    private static async ValueTask<PooledMemory> BuildReferencesFamilyMessageImprintInputCoreAsync(
        bool includeSignatureValue,
        ReadOnlyMemory<byte> signatureValueBase64Url,
        JAdESUnsignedHeaders etsiU,
        int? ownElementIndex,
        string? canonAlg,
        JAdESCanonicalizeUnsignedElementDelegate? canonicalize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(etsiU);
        ArgumentNullException.ThrowIfNull(pool);
        ValidateCanonicalizationArguments(etsiU.Mode, canonAlg, canonicalize);

        int sliceBound = etsiU.Count;
        if(ownElementIndex.HasValue)
        {
            int index = ownElementIndex.Value;
            if(index < 0 || index >= etsiU.Count)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(ownElementIndex),
                    index,
                    "The sigRTst/rfsTst under validation must identify an existing etsiU element.");
            }

            JAdESUnsignedHeaderElement ownElement = etsiU[index];
            string? ownCanonAlg = includeSignatureValue
                ? RequireOwnCanonAlg<JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp>(ownElement, "sigRTst")
                : RequireOwnCanonAlg<JAdESUnsignedHeaderElementReferencesTimestamp>(ownElement, "rfsTst");

            if(etsiU.Mode == JAdESEtsiUIncorporationMode.ClearJson && !string.Equals(canonAlg, ownCanonAlg, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The supplied canonAlg must equal the sigRTst/rfsTst element's own declared canonAlg (structural linkage; ETSI TS 119 182-1 V1.2.1, clause 5.3.1, JA-5.3.1-14).",
                    nameof(canonAlg));
            }

            sliceBound = index;
        }

        IReadOnlyList<JAdESUnsignedHeaderElement> prefix = etsiU.ElementsBefore(sliceBound);

        //sigRTst's own component list includes sigTst (JA-A.1.5.1.1-03); rfsTst's own list does not
        //(JA-A.1.5.2.1-03) -- the two builders filter on genuinely different arm sets, not the same set plus a
        //leading signature value.
        var filtered = new List<JAdESUnsignedHeaderElement>(prefix.Count);
        for(int i = 0; i < prefix.Count; ++i)
        {
            bool qualifies = includeSignatureValue
                ? IsSignatureAndReferencesComponentKind(prefix[i])
                : IsReferencesComponentKind(prefix[i]);

            if(qualifies)
            {
                filtered.Add(prefix[i]);
            }
        }

        using PooledMemory componentsContribution = await GetComponentsContributionAsync().ConfigureAwait(false);

        int prefixLength = includeSignatureValue ? signatureValueBase64Url.Length + 1 : 0;
        int totalLength = prefixLength + componentsContribution.Length;

        IMemoryOwner<byte> storage = pool.Rent(Math.Max(totalLength, 1));
        try
        {
            Span<byte> destination = storage.Memory.Span;
            int offset = 0;
            if(includeSignatureValue)
            {
                signatureValueBase64Url.Span.CopyTo(destination[offset..]);
                offset += signatureValueBase64Url.Length;
                destination[offset++] = Dot;
            }

            componentsContribution.AsReadOnlySpan().CopyTo(destination[offset..]);

            return new PooledMemory(storage, totalLength, CryptoTags.JAdESMessageImprintInput);
        }
        catch
        {
            storage.Dispose();
            throw;
        }

        async ValueTask<PooledMemory> GetComponentsContributionAsync() =>
            etsiU.Mode == JAdESEtsiUIncorporationMode.Base64Url
                ? ConcatenateOpaqueElements(filtered, pool)
                : await ConcatenateCanonicalizedElementsAsync(filtered, canonAlg!, canonicalize!, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Asserts that <paramref name="element"/> is a <typeparamref name="TExpected"/> instance (the
    /// typed-fault discipline, extended to <c>sigRTst</c>/<c>rfsTst</c>) and returns its own declared
    /// <c>canonAlg</c> when clear-mode, or <see langword="null"/> when opaque-mode (nothing decoded, nothing to
    /// compare).
    /// </summary>
    private static string? RequireOwnCanonAlg<TExpected>(JAdESUnsignedHeaderElement element, string expectedKind)
        where TExpected: JAdESUnsignedHeaderElement
    {
        if(element is not TExpected)
        {
            throw new ArgumentException(
                $"The etsiU element under validation must be a {expectedKind} instance; found '{element.Kind}' (ETSI TS 119 182-1 V1.2.1, Annex A.1.5).",
                nameof(element));
        }

        return element switch
        {
            JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp { Carriage: JAdESClearUnsignedValue<AdESTimestampContainer> clear } => clear.Value.CanonAlg,
            JAdESUnsignedHeaderElementReferencesTimestamp { Carriage: JAdESClearUnsignedValue<AdESTimestampContainer> clear } => clear.Value.CanonAlg,
            _ => null
        };
    }


    /// <summary>Determines whether an etsiU element's own arm is one of <c>sigRTst</c>'s five time-stamped components (arm-matched, not label-matched).</summary>
    private static bool IsSignatureAndReferencesComponentKind(JAdESUnsignedHeaderElement element) =>
        element is JAdESUnsignedHeaderElementSignatureTimestamp || IsReferencesComponentKind(element);


    /// <summary>Determines whether an etsiU element's own arm is one of <c>rfsTst</c>'s four time-stamped components (arm-matched, not label-matched).</summary>
    private static bool IsReferencesComponentKind(JAdESUnsignedHeaderElement element) =>
        element is JAdESUnsignedHeaderElementCertificateReferences
            or JAdESUnsignedHeaderElementRevocationReferences
            or JAdESUnsignedHeaderElementAttributeCertificateReferences
            or JAdESUnsignedHeaderElementAttributeRevocationReferences;


    /// <summary>
    /// Validates the shared canonicalization-argument precondition every builder in this class enforces: under
    /// <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>, both <paramref name="canonAlg"/> and
    /// <paramref name="canonicalize"/> are required; under <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>,
    /// supplying EITHER is a typed, fail-closed rejection (JA-5.3.1-15) — not a silently-ignored no-op.
    /// </summary>
    private static void ValidateCanonicalizationArguments(JAdESEtsiUIncorporationMode mode, string? canonAlg, JAdESCanonicalizeUnsignedElementDelegate? canonicalize)
    {
        if(mode == JAdESEtsiUIncorporationMode.ClearJson)
        {
            ArgumentException.ThrowIfNullOrEmpty(canonAlg);
            ArgumentNullException.ThrowIfNull(canonicalize);

            return;
        }

        if(canonAlg is not null || canonicalize is not null)
        {
            throw new ArgumentException(
                "If the etsiU header parameter contains base64url-encoded JSON values, instances of tstContainer " +
                "type shall not have the canonAlg member (ETSI TS 119 182-1 V1.2.1, clause 5.3.1, JA-5.3.1-15); " +
                "a caller-supplied canonAlg/canonicalize delegate under Base64url incorporation is a fail-closed " +
                "violation, not a silently-ignored no-op.",
                canonAlg is not null ? nameof(canonAlg) : nameof(canonicalize));
        }
    }


    /// <summary>
    /// Extracts <paramref name="source"/>'s already-final contribution bytes (JA-5.3.6.2.3-02/-03/-04/-06) — a
    /// pure, borrowed-view switch; this builder performs no encoding, dereferencing, or canonicalization of
    /// its own over a payload.
    /// </summary>
    private static ReadOnlyMemory<byte> GetPayloadContribution(JAdESArchiveTimestampPayloadSource source) => source switch
    {
        JAdESRawPayloadImprintSource raw => raw.PayloadBytes,
        JAdESBase64UrlPayloadImprintSource base64Url => base64Url.Base64UrlPayloadText,
        JAdESSigDProcessedPayloadImprintSource sigD => sigD.ProcessedBytes,
        _ => throw new NotSupportedException($"Unknown payload-source arm '{source.GetType()}'.")
    };


    /// <summary>
    /// Concatenates <paramref name="elements"/>' own opaque wire text, byte-exact, in order (JA-5.3.6.2.3-11/-13,
    /// Annex A.1.5.1.2-04/A.1.5.2.2-02) — the Base64url-incorporation branch, with no canonicalization step of
    /// any kind. Writes directly into a pool-rented buffer (no naked intermediate array).
    /// </summary>
    private static PooledMemory ConcatenateOpaqueElements(IReadOnlyList<JAdESUnsignedHeaderElement> elements, BaseMemoryPool pool)
    {
        int totalLength = 0;
        for(int i = 0; i < elements.Count; ++i)
        {
            totalLength += GetOpaqueWireText(elements[i]).Length;
        }

        IMemoryOwner<byte> storage = pool.Rent(Math.Max(totalLength, 1));
        try
        {
            Span<byte> destination = storage.Memory.Span;
            int offset = 0;
            for(int i = 0; i < elements.Count; ++i)
            {
                ReadOnlyMemory<byte> wireText = GetOpaqueWireText(elements[i]);
                wireText.Span.CopyTo(destination[offset..]);
                offset += wireText.Length;
            }

            return new PooledMemory(storage, totalLength, CryptoTags.JAdESMessageImprintInput);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Concatenates <paramref name="elements"/>' canonicalized octet streams, in order (JA-5.3.6.2.4-02/-04,
    /// Annex A.1.5.1.3-04/A.1.5.2.3-02) — the clear-JSON-incorporation branch, routed entirely through
    /// <paramref name="canonicalize"/> (canonical-form exactness, not raw-byte preservation). The
    /// final assembly writes directly into a pool-rented buffer; each per-element intermediate is
    /// already pool-rented by <paramref name="canonicalize"/> itself.
    /// </summary>
    private static async ValueTask<PooledMemory> ConcatenateCanonicalizedElementsAsync(
        IReadOnlyList<JAdESUnsignedHeaderElement> elements,
        string canonAlg,
        JAdESCanonicalizeUnsignedElementDelegate canonicalize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(elements.Count == 0)
        {
            return PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, CryptoTags.JAdESMessageImprintInput);
        }

        var canonicalized = new PooledMemory[elements.Count];
        try
        {
            int totalLength = 0;
            for(int i = 0; i < elements.Count; ++i)
            {
                canonicalized[i] = await canonicalize(canonAlg, elements[i], pool, cancellationToken).ConfigureAwait(false);
                totalLength += canonicalized[i].Length;
            }

            IMemoryOwner<byte> storage = pool.Rent(Math.Max(totalLength, 1));
            try
            {
                Span<byte> destination = storage.Memory.Span;
                int offset = 0;
                for(int i = 0; i < canonicalized.Length; ++i)
                {
                    canonicalized[i].AsReadOnlySpan().CopyTo(destination[offset..]);
                    offset += canonicalized[i].Length;
                }

                return new PooledMemory(storage, totalLength, CryptoTags.JAdESMessageImprintInput);
            }
            catch
            {
                storage.Dispose();
                throw;
            }
        }
        finally
        {
            for(int i = 0; i < canonicalized.Length; ++i)
            {
                canonicalized[i]?.Dispose();
            }
        }
    }


    /// <summary>
    /// Extracts one <c>etsiU</c> element's own opaque wire-text view under Base64url incorporation — safe by
    /// construction: every mode-reporting arm placed into a <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>
    /// <see cref="JAdESUnsignedHeaders"/> is guaranteed to carry a <see cref="JAdESOpaqueUnsignedValue{TValue}"/>
    /// carriage (<see cref="JAdESUnsignedHeaders"/>'s own constructor/<see cref="JAdESUnsignedHeaders.Append"/>
    /// invariant), and the two mode-agnostic arms (<c>cSig</c>, unknown) always carry wire text directly.
    /// </summary>
    private static ReadOnlyMemory<byte> GetOpaqueWireText(JAdESUnsignedHeaderElement element) => element switch
    {
        JAdESUnsignedHeaderElementSignaturePolicyStore e => ((JAdESOpaqueUnsignedValue<JAdESSignaturePolicyStore>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementCounterSignature e => e.WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementSignatureTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementCertificateValues e => ((JAdESOpaqueUnsignedValue<JAdESCertificateValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementRevocationValues e => ((JAdESOpaqueUnsignedValue<JAdESRevocationValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeCertificateValues e => ((JAdESOpaqueUnsignedValue<JAdESCertificateValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeRevocationValues e => ((JAdESOpaqueUnsignedValue<JAdESRevocationValues>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAnyValidationData e => ((JAdESOpaqueUnsignedValue<JAdESValidationData>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementTimestampValidationData e => ((JAdESOpaqueUnsignedValue<JAdESValidationData>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementArchiveTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementCertificateReferences e => ((JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementRevocationReferences e => ((JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeCertificateReferences e => ((JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementAttributeRevocationReferences e => ((JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementReferencesTimestamp e => ((JAdESOpaqueUnsignedValue<AdESTimestampContainer>)e.Carriage).WireText.AsReadOnlyMemory(),
        JAdESUnsignedHeaderElementUnknown e => e.WireText.AsReadOnlyMemory(),
        _ => throw new NotSupportedException($"Unknown etsiU element arm '{element.GetType()}'.")
    };
}
