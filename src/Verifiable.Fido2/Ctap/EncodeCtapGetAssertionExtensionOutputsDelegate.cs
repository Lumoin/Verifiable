using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes the resolved <c>hmac-secret</c> authenticator extension output value into the
/// <c>authenticatorGetAssertion</c> authData <c>extensions</c> CBOR map bytes — the authenticator-side
/// operation.
/// </summary>
/// <param name="hmacSecret">
/// The encrypted <c>hmac-secret</c> output bytes to emit (CTAP 2.3, section 12.7, snapshot lines
/// 13321-13339: <c>encrypt(sharedSecret, output1)</c> for a one-salt request, <c>encrypt(sharedSecret,
/// output1 || output2)</c> for a two-salt request), or <see langword="null"/> to omit the key entirely
/// (the ga request carried no <c>hmac-secret</c> extension). Borrowed, not owned — the caller retains
/// custody of the underlying pooled buffer.
/// </param>
/// <returns>
/// The encoded <c>extensions</c> map bytes, wrapped in a <see cref="TaggedMemory{T}"/>;
/// <see cref="TaggedMemory{T}.Empty"/> — never an encoded empty CBOR map — when <paramref name="hmacSecret"/>
/// is <see langword="null"/>.
/// </returns>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion</see>: hmac-secret is the first
/// <c>authenticatorGetAssertion</c> extension this authenticator emits an authData <c>extensions</c>
/// output for — <c>credProtect</c>/<c>minPinLength</c> are registration-only, and <c>largeBlobKey</c>
/// deliberately bypasses authData for a TOP-LEVEL response member (CTAP 2.3 §12.3 line 12867). Mirrors
/// <see cref="EncodeCtapMakeCredentialExtensionOutputsDelegate"/>'s seam shape (codec supplied at the
/// composition edge, keeping <c>Verifiable.Fido2</c> serialization-agnostic). The shipped default,
/// <c>Verifiable.Cbor.Ctap.CtapGetAssertionExtensionOutputsCborWriter.Write</c>, is method-group-compatible
/// with this delegate.
/// </para>
/// <para>
/// The returned bytes and their emptiness together determine both the argument
/// <see cref="AuthenticatorDataWriter.Write"/>'s own <c>extensions</c> parameter receives and the
/// <c>ED</c> flag bit the caller sets to match — <c>AuthenticatorDataWriter</c>'s own fail-closed check
/// enforces the two agree, exactly as it does for <c>authenticatorMakeCredential</c>.
/// </para>
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapGetAssertionExtensionOutputsDelegate(ReadOnlyMemory<byte>? hmacSecret);
