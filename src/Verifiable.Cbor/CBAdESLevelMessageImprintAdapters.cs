using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR bindings for the CB-AdES stage-4 (wavecb S4) message-imprint-INPUT seam delegates
/// (<see cref="BuildPayloadTimestampMessageImprintInputDelegate"/>,
/// <see cref="TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate"/>,
/// <see cref="TryBuildReferencesOnlyTimestampMessageImprintInputDelegate"/>) — THIN adapters over the
/// shipped S2 <see cref="CBAdESMessageImprints"/> builders, zero algorithm re-implementation.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Registration mechanism mirrors <see cref="CBAdESSignatureSerialization"/> exactly.</strong> Each
/// delegate TYPE is declared in <c>Verifiable.JCose</c> (<c>CBAdESLevelSerializationDelegates.cs</c>);
/// this class implements each as a <see langword="public static"/> GETTER property of that delegate type
/// (never a mutable field), matching this repo's static-getter convention and the exact registration shape
/// <see cref="CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>/<see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>
/// already established for the S3 seams.
/// </para>
/// <para>
/// <strong>Two of the three seams are a direct method-group assignment, not a lambda.</strong> The shipped
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
}
