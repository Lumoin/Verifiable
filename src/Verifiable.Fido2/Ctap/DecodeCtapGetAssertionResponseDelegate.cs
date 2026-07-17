using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorGetAssertion</c> response into its
/// typed model — the client/RP-side operation.
/// </summary>
/// <param name="payload">
/// The CBOR-encoded response payload (the bytes following the CTAP2 status byte in the response
/// envelope).
/// </param>
/// <param name="pool">
/// The memory pool the returned model's <see cref="CtapGetAssertionResponse.Credential"/> identifier
/// and, when present, its <see cref="CtapGetAssertionResponse.User"/>'s user handle rent from.
/// </param>
/// <returns>The decoded response model. The caller owns and disposes its <see cref="SensitiveMemory"/> carriers.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic. The shipped default,
/// <c>Verifiable.Cbor.Ctap.CtapGetAssertionResponseCborReader.Read</c>, is method-group-compatible with
/// this delegate.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="payload"/> is not valid CTAP2 canonical CBOR, or omits a Required member
/// (<c>credential</c>, <c>authData</c>, or <c>signature</c>).
/// </exception>
public delegate CtapGetAssertionResponse DecodeCtapGetAssertionResponseDelegate(ReadOnlyMemory<byte> payload, MemoryPool<byte> pool);
