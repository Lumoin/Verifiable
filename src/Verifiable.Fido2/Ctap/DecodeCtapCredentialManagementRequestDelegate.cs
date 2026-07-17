using System;
using System.Buffers;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorCredentialManagement</c> request into
/// its typed model — the authenticator-side operation.
/// </summary>
/// <param name="parametersCbor">The CBOR-encoded request parameter map.</param>
/// <param name="pool">The memory pool the decoded <c>credentialId</c>/<c>user</c> carriers rent from.</param>
/// <returns>The decoded request model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapAuthenticatorConfigRequestDelegate"/>'s shape.
/// The shipped default, <c>Verifiable.Cbor.Ctap.CtapCredentialManagementRequestCborReader.Read</c>, is
/// method-group-compatible with this delegate. A REQUIRED
/// <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> constructor parameter (R1: this
/// authenticator advertises <c>credMgmt:true</c> unconditionally, so an advertises-but-cannot-decode
/// configuration is unrepresentable).
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR, or omits the Required
/// <c>subCommand</c> member.
/// </exception>
public delegate CtapCredentialManagementRequest DecodeCtapCredentialManagementRequestDelegate(ReadOnlyMemory<byte> parametersCbor, MemoryPool<byte> pool);
