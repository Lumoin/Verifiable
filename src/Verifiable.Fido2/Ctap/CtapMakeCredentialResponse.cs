using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The subset of the <c>authenticatorMakeCredential</c> response structure this library models: the two
/// Required members plus the attestation statement.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. <c>unsignedExtensionOutputs</c>
/// (<c>0x06</c>) is not modeled this wave. <see cref="AuthData"/> and <see cref="AttStmt"/> carry raw
/// wire bytes rather than a parsed view: this library's <c>AuthenticatorDataWriter</c>/<c>NoneAttestation</c>
/// (or a future attestation format) already produce exactly these bytes, and the WebAuthn client-side
/// <c>attestationObject</c> translation this response feeds needs the same raw bytes verbatim, so no
/// intermediate parse/re-encode step is useful at this layer.
/// </remarks>
/// <param name="Fmt">Required (<c>0x01</c>). The attestation statement format identifier.</param>
/// <param name="AuthData">Required (<c>0x02</c>). The raw <c>authenticatorData</c> wire bytes.</param>
/// <param name="AttStmt">
/// Optional (<c>0x03</c>). The already CBOR-encoded, format-specific attestation statement map, spliced
/// in verbatim. <see langword="null"/> when omitted.
/// </param>
/// <param name="EpAtt">
/// Optional (<c>0x04</c>). Whether an enterprise attestation was returned for this credential (CTAP 2.3
/// §7.1, waveep R6/R9). The AUTHENTICATOR sets this to <see langword="true"/> exactly when mc Step 9
/// granted an enterprise attestation and never emits an explicit <see langword="false"/> — both
/// <see langword="null"/> (absent) and present-<see langword="false"/> are spec-legal encodings of "not
/// returned" (lines 3623-3625), and this authenticator always chooses absence (trap 18). The CODEC stays
/// faithful to whichever value it is given: a foreign present-<see langword="false"/> round-trips
/// unchanged through <c>Verifiable.Cbor.Ctap.CtapMakeCredentialResponseCborWriter</c>.
/// </param>
/// <param name="LargeBlobKey">
/// Optional (<c>0x05</c>). The freshly minted 32-byte <c>largeBlobKey</c> for the just-created credential
/// (CTAP 2.3 §12.3, lines 12851/12853), present iff the request's <c>largeBlobKey</c> extension resolved
/// to <see langword="true"/> AND the credential is discoverable (<c>options.rk == true</c>).
/// <see langword="null"/> when the extension was not requested — line 12828's MUST NOT: the value is
/// never emitted unsolicited. Travels TOP-LEVEL here, never inside <see cref="AuthData"/>'s extensions
/// map (line 12853: "i.e., not in the extensions field of the authenticator data").
/// </param>
[DebuggerDisplay("CtapMakeCredentialResponse(Fmt={Fmt})")]
public sealed record CtapMakeCredentialResponse(
    string Fmt, ReadOnlyMemory<byte> AuthData, ReadOnlyMemory<byte>? AttStmt = null, bool? EpAtt = null, ReadOnlyMemory<byte>? LargeBlobKey = null);
