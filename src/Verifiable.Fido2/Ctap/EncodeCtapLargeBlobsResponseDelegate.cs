namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Encodes an <c>authenticatorLargeBlobs</c> <c>get</c> response model into its CTAP2-canonical CBOR
/// payload bytes — the authenticator-side operation.
/// </summary>
/// <param name="response">The response model to encode.</param>
/// <returns>The encoded payload.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="EncodeCtapCredentialManagementResponseDelegate"/>'s shape.
/// The shipped default, <c>Verifiable.Cbor.Ctap.CtapLargeBlobsResponseCborWriter.Write</c>, is
/// method-group-compatible with this delegate. A REQUIRED
/// <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> constructor parameter: this
/// authenticator advertises <c>largeBlobs:true</c> unconditionally, so an advertises-but-cannot-encode
/// configuration is unrepresentable, the same posture <see cref="EncodeCtapCredentialManagementResponseDelegate"/>
/// establishes for <c>credMgmt</c>. Invoked only for <c>get</c>'s response; a <c>set</c> outcome's bare
/// <c>CTAP2_OK</c> is framed without calling this delegate at all.
/// </remarks>
public delegate TaggedMemory<byte> EncodeCtapLargeBlobsResponseDelegate(CtapLargeBlobsResponse response);
