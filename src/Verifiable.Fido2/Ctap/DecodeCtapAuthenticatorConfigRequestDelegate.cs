using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorConfig</c> request into its typed
/// model — the authenticator-side operation.
/// </summary>
/// <param name="parametersCbor">The CBOR-encoded request parameter map.</param>
/// <returns>The decoded request model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapClientPinRequestDelegate"/>'s shape. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapAuthenticatorConfigRequestCborReader.Read</c>, is
/// method-group-compatible with this delegate. A REQUIRED <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/>
/// constructor parameter (this authenticator advertises <c>authnrCfg:true</c> unconditionally, so an
/// advertises-but-cannot-decode configuration is unrepresentable).
/// </remarks>
/// <exception cref="Fido2FormatException">
/// <paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR, or omits the Required
/// <c>subCommand</c> member.
/// </exception>
public delegate CtapAuthenticatorConfigRequest DecodeCtapAuthenticatorConfigRequestDelegate(ReadOnlyMemory<byte> parametersCbor);
