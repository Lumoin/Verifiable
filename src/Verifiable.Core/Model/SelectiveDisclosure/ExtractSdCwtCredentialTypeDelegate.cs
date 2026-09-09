namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extracts the <c>vct</c> claim (CWT claim 11 = <c>WellKnownCwtClaimNames.Vct</c>)
/// from an SD-CWT's issuer-signed payload — the credential's own declared type — so the
/// verifier can supply it to the Core DCQL metadata extractor.
/// </summary>
/// <remarks>
/// <para>
/// A pure CBOR parse seam — it reads the <c>vct</c> text string from the SD-CWT's
/// COSE_Sign1 payload without any cryptographic validation. Wired by the application
/// to a <c>Verifiable.Cbor</c> implementation — typically
/// <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractCredentialType</c>. The SD-CWT analog of
/// <see cref="ExtractSdCwtIssuerDelegate"/>.
/// </para>
/// </remarks>
/// <param name="sdCwt">The embedded presentation SD-CWT whose issuer-signed payload carries <c>vct</c>.</param>
/// <returns>The <c>vct</c> claim value, or <see langword="null"/> when absent.</returns>
public delegate string? ExtractSdCwtCredentialTypeDelegate(SdToken<System.ReadOnlyMemory<byte>> sdCwt);
