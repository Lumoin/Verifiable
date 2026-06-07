using System;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Reconstructs the Tag 24-wrapped <c>DeviceAuthenticationBytes</c> the device-side COSE_Sign1
/// signature covers, from the session transcript, doctype, and the device-signed half's preserved
/// namespace bytes, per ISO/IEC 18013-5 §9.1.3.4.
/// </summary>
/// <remarks>
/// <para>
/// This is the CBOR seam the device-signature verifier composes but does not perform itself: the
/// wire form carries a nil payload, so the verifier reconstructs the signed payload from the same
/// inputs the wallet used at signing time and feeds it into the COSE Sig_structure. Wired by the
/// application to <c>Verifiable.Cbor.Mdoc.MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.
/// </para>
/// </remarks>
/// <param name="encodedSessionTranscript">The transport-binding's session transcript bytes; MUST match what the device used at signing time.</param>
/// <param name="docType">The enclosing document's docType URI.</param>
/// <param name="encodedDeviceNameSpacesBytes">The device-signed half's preserved Tag 24 DeviceNameSpaces bytes.</param>
/// <returns>The Tag 24-wrapped <c>DeviceAuthenticationBytes</c> that feeds the COSE Sig_structure payload.</returns>
public delegate ReadOnlyMemory<byte> EncodeDeviceAuthenticationBytesDelegate(
    ReadOnlyMemory<byte> encodedSessionTranscript,
    string docType,
    ReadOnlyMemory<byte> encodedDeviceNameSpacesBytes);
