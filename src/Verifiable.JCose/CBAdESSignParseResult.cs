using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// Delegate for the fail-closed parse of CB-AdES <c>COSE_Sign</c> (multi-signer) wire bytes.
/// </summary>
/// <remarks>
/// <para>
/// The <c>COSE_Sign</c> counterpart of <see cref="ParseCBAdESSign1Delegate"/> — it generalizes the CB-AdES
/// wire parse beyond its former COSE_Sign1-only acceptance. RFC 9052
/// §4.1's <c>[protected, unprotected, payload, signatures]</c> 4-array replaces COSE_Sign1's bare signature
/// <c>bstr</c> at the fourth array position with <c>signatures: [+ COSE_Signature]</c> — a sibling delegate,
/// not a widened <see cref="ParseCBAdESSign1Delegate"/>, since the two wire shapes diverge structurally at
/// that position (a single <c>bstr</c> vs. an array of per-signer 3-arrays) the same way
/// <see cref="BuildCoseSignatureSigStructureDelegate"/> is a sibling of <see cref="BuildSigStructureDelegate"/>
/// rather than a widened version of it.
/// </para>
/// <para>
/// Never throws for malformed input; every failure path returns a
/// <see cref="CBAdESSignParseResult"/> with <see cref="CBAdESSignParseResult.IsSuccess"/> <see langword="false"/>.
/// </para>
/// </remarks>
/// <param name="wireBytes">The candidate CB-AdES <c>COSE_Sign</c> wire bytes.</param>
/// <param name="pool">Memory pool the decoded carriers rent their buffers from.</param>
/// <returns>The parse result.</returns>
public delegate CBAdESSignParseResult ParseCBAdESSignDelegate(ReadOnlyMemory<byte> wireBytes, BaseMemoryPool pool);


/// <summary>
/// One signer's decoded <c>COSE_Signature</c> entry within a parsed CB-AdES <c>COSE_Sign</c> message
/// (<see cref="CBAdESSignParseResult.Signers"/>).
/// </summary>
/// <remarks>
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 4.4: "CB-AdES signatures supported by a <c>COSE_Sign</c> structure...
/// may include the <c>uHeaders</c> unprotected header parameter in the signer layer" — <see cref="UnsignedHeaders"/>/
/// <see cref="RawUnsignedHeaders"/> carry that per-signer occurrence, decoded through the SAME
/// <c>CBAdESSerialization.TryParseUnsignedHeaders</c> seam <see cref="CBAdESSign1ParseResult"/>'s own body-layer
/// occurrence uses (the model is layer-agnostic — nothing about it assumes which layer supplied its bytes).
/// <see cref="RawProtectedHeader"/> mirrors <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/>'s own
/// byte-exactness discipline per signer.
/// </remarks>
[DebuggerDisplay("CBAdESSignerParseResult: {Signature}")]
public sealed class CBAdESSignerParseResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESSignerParseResult"/>. Ownership of <paramref name="rawProtectedHeader"/>,
    /// <paramref name="signature"/>, <paramref name="unsignedHeaders"/>, and <paramref name="rawUnsignedHeaders"/>,
    /// when supplied, transfers to this instance.
    /// </summary>
    /// <param name="rawProtectedHeader">See <see cref="RawProtectedHeader"/>.</param>
    /// <param name="signature">See <see cref="Signature"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>.</param>
    /// <param name="rawUnsignedHeaders">See <see cref="RawUnsignedHeaders"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rawProtectedHeader"/> or <paramref name="signature"/> is null.</exception>
    internal CBAdESSignerParseResult(
        EncodedCoseProtectedHeader rawProtectedHeader,
        Signature signature,
        CBAdESUnsignedHeaders? unsignedHeaders,
        EncodedCBAdESUnsignedHeaders? rawUnsignedHeaders)
    {
        ArgumentNullException.ThrowIfNull(rawProtectedHeader);
        ArgumentNullException.ThrowIfNull(signature);

        RawProtectedHeader = rawProtectedHeader;
        Signature = signature;
        UnsignedHeaders = unsignedHeaders;
        RawUnsignedHeaders = rawUnsignedHeaders;
    }


    /// <summary>
    /// Gets this signer's raw, undecoded protected-header wire bytes — RFC 9052 §4.4's <c>sign_protected</c>
    /// byte string, verbatim. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public EncodedCoseProtectedHeader RawProtectedHeader { get; }

    /// <summary>
    /// Gets this signer's decoded signature carrier. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public Signature Signature { get; }

    /// <summary>
    /// Gets this signer's decoded <c>uHeaders</c> unsigned-header set, or <see langword="null"/> when absent
    /// from this signer's own unprotected header map. Owned by this instance when present; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>
    /// Gets this signer's raw, undecoded <c>uHeaders</c> array wire bytes (label 268), or <see langword="null"/>
    /// when absent. Non-null iff <see cref="UnsignedHeaders"/> is non-null. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public EncodedCBAdESUnsignedHeaders? RawUnsignedHeaders { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        RawProtectedHeader.Dispose();
        Signature.Dispose();
        UnsignedHeaders?.Dispose();
        RawUnsignedHeaders?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// The outcome of <see cref="ParseCBAdESSignDelegate"/> — a mint-only decoded CB-AdES <c>COSE_Sign</c>
/// envelope, or a <see cref="IsSuccess"/> <see langword="false"/> failure carrying nothing.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope: the COSE-structural envelope only.</strong> Unlike <see cref="CBAdESSign1ParseResult"/>, this
/// type does not decode either layer's protected-header bytes into a <see cref="CBAdESProtectedHeaders"/>
/// aggregate — that model's own remarks scope it to the <c>COSE_Sign1</c> body layer, and which clause-5.1/5.2
/// components a <c>COSE_Sign</c> body vs. signer layer may carry (including whether <c>alg</c> is mandatory per
/// signer or may live at the body layer) is a CB-AdES-semantic question this type does
/// not resolve — that decode lands with the full CB-AdES-over-COSE_Sign orchestration.
/// What this type DOES guarantee, matching every other CB-AdES parse result in this library: every
/// protected-header occurrence (body and per-signer) is captured as its own exact wire bytes
/// (<see cref="RawBodyProtectedHeader"/>, <see cref="CBAdESSignerParseResult.RawProtectedHeader"/>), and every
/// <c>uHeaders</c> occurrence (signer layer only — clause 4.4 forbids it at the body layer under
/// <c>COSE_Sign</c>) decodes through the SAME layer-agnostic <c>CBAdESUnsignedHeaders</c> model
/// <see cref="CBAdESSign1ParseResult"/> uses, so labels 11/12 (RFC 9338 countersignatures) and every other
/// <c>uHeaders</c> element are visible regardless of which structure carries them.
/// </para>
/// <para>
/// <strong>Structural checks enforced at parse (fail-closed), mirroring <see cref="CBAdESSign1ParseResult"/>'s
/// own precedent for the body layer.</strong> The body-layer unprotected header map must be empty — clause 4.4:
/// "CB-AdES signatures supported by a <c>COSE_Sign</c> structure... shall not contain the <c>uHeaders</c>
/// unprotected header parameter in the body layer," and clause 4.4's opening sentence permits no OTHER member
/// either. Each signer's own unprotected header map may contain at most the one <c>uHeaders</c> member, exactly
/// like <see cref="CBAdESSign1ParseResult"/>'s body layer. <c>signatures</c> must be non-empty (RFC 9052 §4.1,
/// <c>[+ COSE_Signature]</c>).
/// </para>
/// </remarks>
public sealed class CBAdESSignParseResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESSignParseResult"/>. Ownership of <paramref name="rawBodyProtectedHeader"/>
    /// and every entry of <paramref name="signers"/>, when supplied, transfers to this instance.
    /// </summary>
    /// <param name="isSuccess">See <see cref="IsSuccess"/>.</param>
    /// <param name="rawBodyProtectedHeader">See <see cref="RawBodyProtectedHeader"/>.</param>
    /// <param name="payloadIsPresent">See <see cref="PayloadIsPresent"/>.</param>
    /// <param name="payload">See <see cref="Payload"/>.</param>
    /// <param name="signers">See <see cref="Signers"/>.</param>
    internal CBAdESSignParseResult(
        bool isSuccess,
        EncodedCoseProtectedHeader? rawBodyProtectedHeader,
        bool payloadIsPresent,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<CBAdESSignerParseResult>? signers)
    {
        IsSuccess = isSuccess;
        RawBodyProtectedHeader = rawBodyProtectedHeader;
        PayloadIsPresent = payloadIsPresent;
        Payload = payload;
        Signers = signers;
    }


    /// <summary>
    /// Gets whether the wire bytes decoded into a structurally well-formed CB-AdES <c>COSE_Sign</c>. When
    /// <see langword="false"/>, every other member is at its default (<see langword="null"/>/empty).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the body layer's raw, undecoded protected-header wire bytes, or <see langword="null"/> when
    /// <see cref="IsSuccess"/> is <see langword="false"/>. Non-null iff <see cref="IsSuccess"/> is
    /// <see langword="true"/> — clause 4.4 permits the body layer to carry protected header parameters (or
    /// none, a genuinely empty map), so a well-formed message always yields a (possibly empty) byte string
    /// here. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public EncodedCoseProtectedHeader? RawBodyProtectedHeader { get; }

    /// <summary>
    /// Gets whether the wire COSE Payload slot carried a (possibly zero-length) byte string, as opposed to the
    /// CBOR <c>nil</c> detached sentinel (clause 4.5), mirroring <see cref="CBAdESSign1ParseResult.PayloadIsPresent"/>.
    /// </summary>
    public bool PayloadIsPresent { get; }

    /// <summary>
    /// Gets the payload bytes when <see cref="PayloadIsPresent"/> is <see langword="true"/>; otherwise empty.
    /// <strong>Borrowed/GC-owned</strong> view — safe to hold past this instance's <see cref="Dispose"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Gets the per-signer decoded entries, in wire order, or <see langword="null"/> when <see cref="IsSuccess"/>
    /// is <see langword="false"/>. Non-empty iff <see cref="IsSuccess"/> is <see langword="true"/> (RFC 9052
    /// §4.1's <c>[+ COSE_Signature]</c> is non-empty by construction). Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CBAdESSignerParseResult>? Signers { get; }


    /// <summary>
    /// Mints a successful result. Ownership of <paramref name="rawBodyProtectedHeader"/> and every entry of
    /// <paramref name="signers"/> transfers to the returned instance.
    /// </summary>
    /// <param name="rawBodyProtectedHeader">The body layer's raw protected-header wire bytes.</param>
    /// <param name="payloadIsPresent">See <see cref="PayloadIsPresent"/>.</param>
    /// <param name="payload">The payload bytes; see <see cref="Payload"/>.</param>
    /// <param name="signers">The per-signer decoded entries, in wire order.</param>
    /// <returns>A successful <see cref="CBAdESSignParseResult"/>.</returns>
    internal static CBAdESSignParseResult Success(
        EncodedCoseProtectedHeader rawBodyProtectedHeader,
        bool payloadIsPresent,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<CBAdESSignerParseResult> signers) =>
        new(true, rawBodyProtectedHeader, payloadIsPresent, payload, signers);


    /// <summary>Mints a failed result carrying no decoded content.</summary>
    /// <returns>A failed <see cref="CBAdESSignParseResult"/>.</returns>
    internal static CBAdESSignParseResult Failure() => new(false, null, false, ReadOnlyMemory<byte>.Empty, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        RawBodyProtectedHeader?.Dispose();
        if(Signers is not null)
        {
            foreach(CBAdESSignerParseResult signer in Signers)
            {
                signer.Dispose();
            }
        }

        disposed = true;
    }
}
