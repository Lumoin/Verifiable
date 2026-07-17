using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorGetAssertion</c> request structure: every parameter this library models,
/// including the ClientPIN parameters this wave's authenticator always rejects, so the
/// authenticator-side handler can see them and produce the spec-mandated error.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>. <see cref="Options"/> decodes an
/// <c>rk</c> key if the wire carries one even though "a platform MUST NOT send the 'rk' option key" —
/// see <see cref="CtapCommandOptions"/>'s own remarks on why this codec layer does not silently drop
/// that distinction. <see cref="Extensions"/> carries TWO pre-decoded known-key convenience members:
/// <see cref="LargeBlobKey"/> (scalar, the <see cref="CtapMakeCredentialRequest.CredProtect"/>/
/// <see cref="CtapMakeCredentialRequest.MinPinLength"/> precedent applied to this request type first,
/// wavelb R8) and <see cref="HmacSecret"/> (compound, this request type's first non-scalar extension
/// value, CTAP 2.3 §12.7).
/// </remarks>
/// <param name="RpId">Required (<c>0x01</c>). The relying party identifier.</param>
/// <param name="ClientDataHash">
/// Required (<c>0x02</c>). The 32-byte hash of the client data, computed by the client.
/// </param>
/// <param name="AllowList">
/// Optional (<c>0x03</c>). The credentials the authenticator may generate an assertion for. A platform
/// MUST NOT send an empty <c>allowList</c> — if it would be empty it MUST be omitted instead;
/// <see langword="null"/> when omitted.
/// </param>
/// <param name="Extensions">
/// Optional (<c>0x04</c>). The still-CBOR-encoded extension-identifier-keyed map, opaque at this layer.
/// <see langword="null"/> when omitted.
/// </param>
/// <param name="Options">Optional (<c>0x05</c>). The <c>up</c>/<c>uv</c> (and illegal <c>rk</c>) option values.</param>
/// <param name="PinUvAuthParam">
/// Optional (<c>0x06</c>), ClientPIN-only. The decoded byte-string content; <see langword="null"/> when
/// omitted.
/// </param>
/// <param name="PinUvAuthProtocol">Optional (<c>0x07</c>), ClientPIN-only. The PIN/UV protocol version.</param>
/// <param name="LargeBlobKey">
/// Decoded from <see cref="Extensions"/>'s own <c>largeBlobKey</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey"/>): the requested boolean value,
/// exactly as it arrived on the wire — <see langword="null"/> when <see cref="Extensions"/> is absent or
/// carries no <c>largeBlobKey</c> key. CTAP 2.3 §12.3 (lines 12860/12865): any present value other than
/// <see langword="true"/> is a request-shape error (<c>CTAP2_ERR_INVALID_OPTION</c>).
/// </param>
/// <param name="HmacSecret">
/// Decoded from <see cref="Extensions"/>'s own <c>hmac-secret</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.HmacSecret"/>): the compound
/// keyAgreement/saltEnc/saltAuth/pinUvAuthProtocol input (CTAP 2.3 §12.7, snapshot lines 13228-13248),
/// or <see langword="null"/> when <see cref="Extensions"/> is absent or carries no <c>hmac-secret</c>
/// key.
/// </param>
[DebuggerDisplay("CtapGetAssertionRequest(RpId={RpId})")]
public sealed record CtapGetAssertionRequest(
    string RpId,
    DigestValue ClientDataHash,
    IReadOnlyList<PublicKeyCredentialDescriptor>? AllowList = null,
    ReadOnlyMemory<byte>? Extensions = null,
    CtapCommandOptions? Options = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null,
    int? PinUvAuthProtocol = null,
    bool? LargeBlobKey = null,
    CtapGetAssertionHmacSecretInput? HmacSecret = null);
