using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR bindings for the CB-AdES message-imprint-INPUT seam delegates
/// (<see cref="BuildPayloadTimestampMessageImprintInputDelegate"/>,
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/>,
/// <see cref="TryBuildReferencesOnlyTimestampMessageImprintInputDelegate"/>, and
/// <see cref="TryBuildArchiveTimestampValidationMessageImprintInputDelegate"/>) — THIN adapters over the
/// shipped <see cref="CBAdESMessageImprints"/> builders, zero algorithm re-implementation.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Registration mechanism mirrors <see cref="CBAdESSignatureSerialization"/> exactly.</strong> Each
/// delegate TYPE is declared in <c>Verifiable.JCose</c> (<c>CBAdESLevelSerializationDelegates.cs</c>);
/// this class implements each as a <see langword="public static"/> GETTER property of that delegate type
/// (never a mutable field), matching this repo's static-getter convention and the exact registration shape
/// <see cref="CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>/<see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>
/// already established for those seams.
/// </para>
/// <para>
/// <strong>Two of the five seams are a direct method-group assignment, not a lambda.</strong> The shipped
/// <see cref="CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput"/> and
/// <see cref="CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput"/> already take only
/// JCose/Cryptography-visible types (<see cref="ReadOnlyMemory{T}"/>, <see cref="BaseMemoryPool"/>,
/// <see cref="PooledMemory"/>) — their signatures ALREADY match the delegate types byte-for-byte, so the
/// registration is a bare method reference, the truest possible "thin adapter."
/// </para>
/// <para>
/// <strong>The third seam translates a mirror union, then delegates.</strong>
/// <see cref="CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput"/> takes
/// <see cref="CBAdESPayloadImprintSource"/> — Cbor-only shared vocabulary (that type's own remarks explain
/// why it lives here rather than in a COSE-free layer) that cannot appear in a JCose delegate's public
/// signature. <see cref="BuildPayloadTimestampMessageImprintInput"/> therefore takes the JCose-visible
/// mirror <see cref="CBAdESPayloadTimestampImprintSource"/> and performs a purely STRUCTURAL translation
/// (<see cref="ToCborImprintSource"/>) before calling straight into the shipped builder — the byte-assembly
/// algorithm itself is never duplicated.
/// </para>
/// <para>
/// <strong>The fourth and fifth seams reuse the third seam's mirror union.</strong>
/// <see cref="TryBuildArchiveTimestampValidationMessageImprintInput"/> and
/// <see cref="TryBuildArchiveTimestampGenerationMessageImprintInput"/> both take the SAME
/// <see cref="CBAdESPayloadTimestampImprintSource"/> mirror <see cref="BuildPayloadTimestampMessageImprintInput"/>
/// already translates (clause 5.3.5.3 steps 6/7 branch identically to clause 5.2.6 — no new payload-source
/// type). Both un-pin from their former COSE_Sign1-only assumption — the
/// caller now supplies step 2's structure context, step 4's signer-layer header, and step 8's RFC 9338
/// <c>other_fields</c> explicitly, translated via <see cref="ToCborStructureContext"/> (a second mirror
/// translation, the same shape as <see cref="ToCborImprintSource"/>) and threaded straight through otherwise.
/// </para>
/// </remarks>
public static class CBAdESLevelMessageImprintAdapters
{
    /// <summary>
    /// Gets a delegate that builds the <c>adoTst</c> message-imprint input (clause 5.2.6) by translating
    /// <see cref="CBAdESPayloadTimestampImprintSource"/> into its Cbor-only mirror
    /// <see cref="CBAdESPayloadImprintSource"/> and delegating to
    /// <see cref="CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput"/>.
    /// </summary>
    public static BuildPayloadTimestampMessageImprintInputDelegate BuildPayloadTimestampMessageImprintInput { get; } =
        static (source, pool) => CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(ToCborImprintSource(source), pool);


    /// <summary>
    /// Gets a delegate that builds the <c>sigRTst</c> message-imprint input (Annex A.1.2.1.2) — a direct
    /// method-group reference to <see cref="CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput"/>,
    /// whose signature already matches <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/>
    /// exactly.
    /// </summary>
    public static TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate TryBuildSignatureAndReferencesTimestampMessageImprintInput { get; } =
        CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput;


    /// <summary>
    /// Gets a delegate that builds the <c>rfsTst</c> message-imprint input (Annex A.1.2.2.2) — a direct
    /// method-group reference to <see cref="CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput"/>,
    /// whose signature already matches <see cref="TryBuildReferencesOnlyTimestampMessageImprintInputDelegate"/>
    /// exactly.
    /// </summary>
    public static TryBuildReferencesOnlyTimestampMessageImprintInputDelegate TryBuildReferencesOnlyTimestampMessageImprintInput { get; } =
        CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput;


    /// <summary>
    /// Gets a delegate that builds the <c>arcTst</c> message-imprint input in VALIDATION mode (clause 5.3.5.3),
    /// translating <see cref="CBAdESPayloadTimestampImprintSource"/> via <see cref="ToCborImprintSource"/> and
    /// <see cref="CBAdESImprintStructureContext"/> via <see cref="ToCborStructureContext"/>, threading the
    /// caller-supplied signer-layer header and <c>other_fields</c> straight through.
    /// </summary>
    public static TryBuildArchiveTimestampValidationMessageImprintInputDelegate TryBuildArchiveTimestampValidationMessageImprintInput { get; } =
        static (
            CBAdESImprintStructureContext structureContext,
            ReadOnlyMemory<byte> bodyProtectedHeader,
            ReadOnlyMemory<byte>? signerProtectedHeader,
            ReadOnlyMemory<byte> externallySuppliedData,
            CBAdESPayloadTimestampImprintSource payloadSource,
            ReadOnlyMemory<byte>? countersignatureOtherFields,
            ReadOnlyMemory<byte> signatureValue,
            ReadOnlyMemory<byte>? uHeadersEncodedArray,
            int arcTstElementIndex,
            BaseMemoryPool pool,
            out PooledMemory? result) =>
        {
            var context = new CBAdESArchiveTimestampImprintContext
            {
                StructureContext = ToCborStructureContext(structureContext),
                BodyProtectedHeader = bodyProtectedHeader,
                SignerProtectedHeader = signerProtectedHeader,
                ExternallySuppliedData = externallySuppliedData,
                PayloadSource = ToCborImprintSource(payloadSource),
                CountersignatureOtherFields = countersignatureOtherFields,
                SignatureValue = signatureValue,
                UHeadersEncodedArray = uHeadersEncodedArray
            };

            return CBAdESMessageImprints.TryBuildArchiveTimestampValidationMessageImprintInput(context, arcTstElementIndex, pool, out result);
        };


    /// <summary>
    /// Gets a delegate that builds the <c>arcTst</c> message-imprint input in GENERATION mode (clause 5.3.5.3,
    /// steps 10/11 over EVERY <c>uHeaders</c> element already present), translating
    /// <see cref="CBAdESPayloadTimestampImprintSource"/> via <see cref="ToCborImprintSource"/> and
    /// <see cref="CBAdESImprintStructureContext"/> via <see cref="ToCborStructureContext"/>, identically to its
    /// validation-mode sibling.
    /// </summary>
    public static TryBuildArchiveTimestampGenerationMessageImprintInputDelegate TryBuildArchiveTimestampGenerationMessageImprintInput { get; } =
        static (
            CBAdESImprintStructureContext structureContext,
            ReadOnlyMemory<byte> bodyProtectedHeader,
            ReadOnlyMemory<byte>? signerProtectedHeader,
            ReadOnlyMemory<byte> externallySuppliedData,
            CBAdESPayloadTimestampImprintSource payloadSource,
            ReadOnlyMemory<byte>? countersignatureOtherFields,
            ReadOnlyMemory<byte> signatureValue,
            ReadOnlyMemory<byte>? uHeadersEncodedArray,
            BaseMemoryPool pool,
            out PooledMemory? result) =>
        {
            var context = new CBAdESArchiveTimestampImprintContext
            {
                StructureContext = ToCborStructureContext(structureContext),
                BodyProtectedHeader = bodyProtectedHeader,
                SignerProtectedHeader = signerProtectedHeader,
                ExternallySuppliedData = externallySuppliedData,
                PayloadSource = ToCborImprintSource(payloadSource),
                CountersignatureOtherFields = countersignatureOtherFields,
                SignatureValue = signatureValue,
                UHeadersEncodedArray = uHeadersEncodedArray
            };

            return CBAdESMessageImprints.TryBuildArchiveTimestampGenerationMessageImprintInput(context, pool, out result);
        };


    /// <summary>
    /// Translates the JCose-visible <see cref="CBAdESPayloadTimestampImprintSource"/> into the Cbor-only
    /// <see cref="CBAdESPayloadImprintSource"/> arm it mirrors — a purely structural mapping, never
    /// re-implementing any part of the message-imprint algorithm itself.
    /// </summary>
    /// <param name="source">The JCose-visible source to translate.</param>
    /// <returns>The equivalent Cbor-only source.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
    /// <exception cref="NotSupportedException"><paramref name="source"/> is an unknown arm.</exception>
    private static CBAdESPayloadImprintSource ToCborImprintSource(CBAdESPayloadTimestampImprintSource source)
    {
        ArgumentNullException.ThrowIfNull(source);

        return source switch
        {
            CBAdESAttachedPayloadTimestampImprintSource attached => new CBAdESAttachedPayloadImprintSource(attached.PayloadBytes),
            CBAdESDetachedPayloadTimestampImprintSource detached => new CBAdESDetachedPayloadImprintSource(detached.PayloadBytes),
            CBAdESSigDProcessedPayloadTimestampImprintSource sigD => new CBAdESSigDProcessedPayloadImprintSource(sigD.ProcessedParBytes),
            _ => throw new NotSupportedException($"Unknown {nameof(CBAdESPayloadTimestampImprintSource)} arm '{source.GetType()}'.")
        };
    }


    /// <summary>
    /// Translates the JCose-visible <see cref="CBAdESImprintStructureContext"/> into the Cbor-only
    /// <see cref="CBAdESSignatureStructureContext"/> arm it mirrors — a purely structural
    /// mapping, mirroring <see cref="ToCborImprintSource"/>'s own shape.
    /// </summary>
    /// <param name="context">The JCose-visible structure context to translate.</param>
    /// <returns>The equivalent Cbor-only structure context.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    /// <exception cref="NotSupportedException"><paramref name="context"/> is an unknown arm.</exception>
    private static CBAdESSignatureStructureContext ToCborStructureContext(CBAdESImprintStructureContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context switch
        {
            CBAdESImprintCoseSignStructureContext => CBAdESCoseSignStructureContext.Instance,
            CBAdESImprintCoseSign1StructureContext => CBAdESCoseSign1StructureContext.Instance,
            CBAdESImprintCountersignatureStructureContext countersignature => new CBAdESCountersignatureStructureContext(countersignature.ContextText),
            _ => throw new NotSupportedException($"Unknown {nameof(CBAdESImprintStructureContext)} arm '{context.GetType()}'.")
        };
    }
}
