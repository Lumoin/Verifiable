namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Parses an SD-CWT wire form (a COSE_Sign1 carrying the holder-selected
/// disclosures in its <c>sd_claims</c> unprotected header) into a structured
/// <see cref="SdToken{TEnvelope}"/> with the CBOR envelope shape
/// (<see cref="System.ReadOnlyMemory{T}"/> of <see cref="byte"/>).
/// </summary>
/// <remarks>
/// <para>
/// Wired by the application to its SD-CWT implementation — typically
/// <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ParseEmbeddedSdCwt</c> with the
/// application's salt tag and memory pool baked in. The returned token owns the
/// parsed disclosures (and their salts); the caller disposes it.
/// </para>
/// </remarks>
/// <param name="sdCwt">The SD-CWT COSE_Sign1 wire bytes (the embedded presentation token).</param>
/// <returns>The structured token, including issuer COSE_Sign1 and all holder-selected disclosures.</returns>
public delegate SdToken<System.ReadOnlyMemory<byte>> ParseSdCwtTokenDelegate(System.ReadOnlyMemory<byte> sdCwt);
