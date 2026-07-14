using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorMakeCredential</c> request structure: every parameter this library models,
/// including the ClientPIN parameters this authenticator always rejects when unsupported, and the
/// <see cref="EnterpriseAttestation"/> parameter, which mc Step 9 evaluates against the authenticator's
/// own capability/enablement state and pre-configured RP ID list (CTAP 2.3 §7.1, waveep R4-R6) to decide
/// whether to grant an enterprise attestation.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>. <see cref="Extensions"/> and
/// <see cref="PinUvAuthParam"/> carry their wire bytes opaquely — no ClientPIN codec is modeled this
/// wave, so presence (and, for <see cref="PinUvAuthParam"/>, the byte content) is all a handler needs to
/// apply the shared "any <c>pinUvAuthParam</c> is rejected" guard. <see cref="CredProtect"/>,
/// <see cref="MinPinLength"/>, <see cref="LargeBlobKey"/>, <see cref="HmacSecret"/>, and
/// <see cref="HmacSecretMc"/> are <see cref="Extensions"/>'s own five known-key members, decoded for
/// convenience — the exact <c>CtapAuthenticatorConfigRequest.NewMinPinLength</c>/
/// <c>MinPinLengthRpIds</c> precedent of "raw bytes preserved AND selected members pre-decoded" — while
/// every other extension-map key stays covered only by <see cref="Extensions"/>'s own opaque bytes, per
/// CTAP 2.3 section 6.1.2 line 3553's "process any extensions that this authenticator supports, ignoring
/// any that it does not support" rule.
/// </remarks>
/// <param name="ClientDataHash">
/// Required (<c>0x01</c>). The 32-byte hash of the client data, computed by the client.
/// </param>
/// <param name="Rp">Required (<c>0x02</c>). The relying party the credential will be associated with.</param>
/// <param name="User">Required (<c>0x03</c>). The user account the credential will be associated with.</param>
/// <param name="PubKeyCredParams">
/// Required (<c>0x04</c>). The ordered, most-to-least-preferred list of acceptable algorithms. MUST NOT
/// contain duplicate entries.
/// </param>
/// <param name="ExcludeList">
/// Optional (<c>0x05</c>). Credentials the authenticator must reject the request for if already
/// present. MUST NOT be empty if present; <see langword="null"/> when omitted.
/// </param>
/// <param name="Extensions">
/// Optional (<c>0x06</c>). The still-CBOR-encoded extension-identifier-keyed map, opaque at this layer.
/// <see langword="null"/> when omitted.
/// </param>
/// <param name="Options">Optional (<c>0x07</c>). The <c>rk</c>/<c>up</c>/<c>uv</c> option values.</param>
/// <param name="PinUvAuthParam">
/// Optional (<c>0x08</c>), ClientPIN-only. The decoded byte-string content; <see langword="null"/> when
/// omitted.
/// </param>
/// <param name="PinUvAuthProtocol">Optional (<c>0x09</c>), ClientPIN-only. The PIN/UV protocol version.</param>
/// <param name="EnterpriseAttestation">
/// Optional (<c>0x0A</c>), enterprise-attestation-capable authenticators only.
/// </param>
/// <param name="AttestationFormatsPreference">
/// Optional (<c>0x0B</c>). The client/RP's prioritized attestation statement format preference.
/// </param>
/// <param name="CredProtect">
/// Decoded from <see cref="Extensions"/>'s own <c>credProtect</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.CredProtect"/>): the requested integer value,
/// exactly as it arrived on the wire — <see langword="null"/> when <see cref="Extensions"/> is absent or
/// carries no <c>credProtect</c> key. Whether the value is one of the three CTAP 2.3 section 12.1 legal
/// levels ({1, 2, 3}) is a transition-level concern, not this reader's.
/// </param>
/// <param name="MinPinLength">
/// Decoded from <see cref="Extensions"/>'s own <c>minPinLength</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.MinPinLength"/>): the requested boolean value,
/// exactly as it arrived on the wire (including an explicit <see langword="false"/>, distinct from
/// absence) — <see langword="null"/> when <see cref="Extensions"/> is absent or carries no
/// <c>minPinLength</c> key.
/// </param>
/// <param name="LargeBlobKey">
/// Decoded from <see cref="Extensions"/>'s own <c>largeBlobKey</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey"/>): the requested boolean value,
/// exactly as it arrived on the wire (including an explicit <see langword="false"/>, distinct from
/// absence) — <see langword="null"/> when <see cref="Extensions"/> is absent or carries no
/// <c>largeBlobKey</c> key. CTAP 2.3 §12.3 (lines 12842/12847): any present value other than
/// <see langword="true"/> is a request-shape error (<c>CTAP2_ERR_INVALID_OPTION</c>), not a silent
/// no-op — "the extension should be omitted rather than asserted to be false".
/// </param>
/// <param name="HmacSecret">
/// Decoded from <see cref="Extensions"/>'s own <c>hmac-secret</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.HmacSecret"/>): the requested boolean value,
/// exactly as it arrived on the wire (including an explicit <see langword="false"/>, distinct from
/// absence) — <see langword="null"/> when <see cref="Extensions"/> is absent or carries no
/// <c>hmac-secret</c> key. CTAP 2.3 §12.7 (snapshot line 13194): whether the annotation is emitted is a
/// transition-level concern (contract R3 — only literal <see langword="true"/> grants it); this reader
/// reports whatever value arrived on the wire, mirroring <see cref="MinPinLength"/>'s own
/// preserve-the-explicit-false convention.
/// </param>
/// <param name="HmacSecretMc">
/// Decoded from <see cref="Extensions"/>'s own <c>hmac-secret-mc</c> key
/// (<see cref="WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc"/>): the compound
/// keyAgreement/saltEnc/saltAuth/pinUvAuthProtocol map, the SAME shape
/// <see cref="CtapGetAssertionRequest.HmacSecret"/> decodes for <c>authenticatorGetAssertion</c>'s own
/// <c>hmac-secret</c> input (CTAP 2.3 §12.8, snapshot line 13402: "the same as the hmac secret
/// extension's getAssertion input") — <see langword="null"/> when <see cref="Extensions"/> is absent or
/// carries no <c>hmac-secret-mc</c> key. The R6 pairing gate (present while <see cref="HmacSecret"/> is
/// absent or not exactly <see langword="true"/> is a request-shape error, CTAP 2.3 §12.8 snapshot line
/// 13370) is a transition-level concern, not this reader's.
/// </param>
[DebuggerDisplay("CtapMakeCredentialRequest(Rp={Rp}, User={User})")]
public sealed record CtapMakeCredentialRequest(
    DigestValue ClientDataHash,
    CtapPublicKeyCredentialRpEntity Rp,
    CtapPublicKeyCredentialUserEntity User,
    IReadOnlyList<PublicKeyCredentialParameters> PubKeyCredParams,
    IReadOnlyList<PublicKeyCredentialDescriptor>? ExcludeList = null,
    ReadOnlyMemory<byte>? Extensions = null,
    CtapCommandOptions? Options = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null,
    int? PinUvAuthProtocol = null,
    int? EnterpriseAttestation = null,
    IReadOnlyList<string>? AttestationFormatsPreference = null,
    int? CredProtect = null,
    bool? MinPinLength = null,
    bool? LargeBlobKey = null,
    bool? HmacSecret = null,
    CtapGetAssertionHmacSecretInput? HmacSecretMc = null);
