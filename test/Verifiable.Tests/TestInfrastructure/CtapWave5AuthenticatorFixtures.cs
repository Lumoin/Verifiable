using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP <c>authenticatorClientPIN</c> test suite — the three read-only
/// subcommands (<c>getPINRetries</c>, <c>getKeyAgreement</c>, <c>getUVRetries</c>), the four PIN-path
/// subcommands (<c>setPIN</c>, <c>changePIN</c>, <c>getPinToken</c>,
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>), and the built-in-UV token-issuance subcommand
/// (<c>getPinUvAuthTokenUsingUvWithPermissions</c>) alike: simulator composition wired with the shipped
/// clientPIN codecs, factored once here rather than reimplemented per test category — mirrors
/// <see cref="CtapWave2AuthenticatorFixtures"/>'s role for the make-credential/get-assertion surface.
/// </summary>
internal static class CtapWave5AuthenticatorFixtures
{
    /// <summary>
    /// Builds a single-entry <c>get_assertion</c> <c>allowList</c> wrapping <paramref name="credentialIdBytes"/>
    /// as a <see cref="WellKnownPublicKeyCredentialTypes.PublicKey"/> descriptor.
    /// </summary>
    /// <param name="credentialIdBytes">The credential identifier bytes.</param>
    /// <param name="pool">The pool the wrapped <see cref="CredentialId"/> carrier rents from.</param>
    /// <returns>The single-entry allow list.</returns>
    internal static IReadOnlyList<PublicKeyCredentialDescriptor> BuildAllowList(byte[] credentialIdBytes, MemoryPool<byte> pool) =>
        [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }];


    /// <summary>
    /// Builds a simulator wired with every shipped CBOR codec, including
    /// <c>authenticatorClientPIN</c>'s request/response codecs — no <c>authenticatorClientPIN</c>
    /// subcommand mints a credential, so no <see cref="CtapCredentialSigningBackend"/> is supplied.
    /// </summary>
    /// <param name="runId">A stable identifier for the simulated authenticator.</param>
    /// <param name="rng">
    /// The random-number backend the AAGUID and every minted credential identifier are drawn from, or
    /// <see langword="null"/> for the production default. The PIN/UV key-agreement key pairs are drawn
    /// independently, through the registered production key-creation seam, regardless of this value.
    /// </param>
    /// <returns>The composed simulator. The caller owns it and must dispose it.</returns>
    public static CtapAuthenticatorSimulator CreateSimulator(string runId, FillEntropyDelegate? rng = null) =>
        new(
            runId,
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            rng: rng,
            decodeClientPinRequest: CtapClientPinRequestCborReader.Read,
            encodeClientPinResponse: CtapClientPinResponseCborWriter.Write,
            decodeAuthenticatorConfigRequest: CtapAuthenticatorConfigRequestCborReader.Read,
            decodeCredentialManagementRequest: CtapCredentialManagementRequestCborReader.Read,
            encodeCredentialManagementResponse: CtapCredentialManagementResponseCborWriter.Write,
            decodeBioEnrollmentRequest: CtapBioEnrollmentRequestCborReader.Read,
            encodeBioEnrollmentResponse: CtapBioEnrollmentResponseCborWriter.Write,
            decodeLargeBlobsRequest: CtapLargeBlobsRequestCborReader.Read,
            encodeLargeBlobsResponse: CtapLargeBlobsResponseCborWriter.Write,
            encodeMakeCredentialExtensionOutputs: CtapMakeCredentialExtensionOutputsCborWriter.Write,
            encodeGetAssertionExtensionOutputs: CtapGetAssertionExtensionOutputsCborWriter.Write);
}
