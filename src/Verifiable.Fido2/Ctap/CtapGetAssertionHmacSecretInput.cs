using System;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The decoded <c>authenticatorGetAssertion</c> <c>"hmac-secret"</c> extension input: the compound map
/// CTAP 2.3 section 12.7 defines under <see cref="CtapGetAssertionRequest.Extensions"/>'s
/// <c>"hmac-secret"</c> key — this request type's first COMPOUND (non-scalar) pre-decoded extension
/// convenience member, alongside the scalar <see cref="CtapGetAssertionRequest.LargeBlobKey"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension">
/// CTAP 2.3, section 12.7: HMAC Secret Extension (hmac-secret)</see>, snapshot lines 13228-13248. Also
/// the shape section 12.8 (snapshot line 13402, contract R6) reuses verbatim for
/// <c>"hmac-secret-mc"</c>'s own <c>authenticatorMakeCredential</c> input.
/// </remarks>
/// <param name="KeyAgreement">
/// The <see cref="WellKnownCtapHmacSecretExtensionKeys.KeyAgreement"/> member: the platform's ephemeral
/// key-agreement COSE_Key, decapsulated against the authenticator's own protocol key pair exactly as
/// every other PIN/UV auth protocol operation does (seams §2).
/// </param>
/// <param name="SaltEnc">
/// The <see cref="WellKnownCtapHmacSecretExtensionKeys.SaltEnc"/> member: <c>encrypt(sharedSecret,
/// salt1)</c> (one salt) or <c>encrypt(sharedSecret, salt1 || salt2)</c> (two salts). Opaque ciphertext
/// at this layer — protocol two's own IV-prefixed shape (48/80 bytes) is a processing-time concern
/// (contract R4 step 6, trap 7), never validated by length here.
/// </param>
/// <param name="SaltAuth">
/// The <see cref="WellKnownCtapHmacSecretExtensionKeys.SaltAuth"/> member: <c>authenticate(sharedSecret,
/// saltEnc)</c>.
/// </param>
/// <param name="PinUvAuthProtocol">
/// The <see cref="WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol"/> member, or
/// <see langword="null"/> when omitted — defaulting (absent implies protocol one, snapshot line 13279)
/// and unsupported-value rejection (snapshot line 13281's antecedent-false branch; contract R4 step 1's
/// clientPIN-analog ruling for a present-but-unsupported value) are both processing-time concerns, not
/// this reader's.
/// </param>
public sealed record CtapGetAssertionHmacSecretInput(
    CoseKey KeyAgreement,
    ReadOnlyMemory<byte> SaltEnc,
    ReadOnlyMemory<byte> SaltAuth,
    int? PinUvAuthProtocol);
