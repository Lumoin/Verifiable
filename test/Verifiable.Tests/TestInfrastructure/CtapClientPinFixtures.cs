using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Fido2.Ctap.Authenticator.Custody;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP <c>authenticatorClientPIN</c> test suite — the three read-only
/// subcommands (<c>getPINRetries</c>, <c>getKeyAgreement</c>, <c>getUVRetries</c>), the four PIN-path
/// subcommands (<c>setPIN</c>, <c>changePIN</c>, <c>getPinToken</c>,
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>), and the built-in-UV token-issuance subcommand
/// (<c>getPinUvAuthTokenUsingUvWithPermissions</c>) alike: simulator composition wired with the shipped
/// clientPIN codecs, factored once here rather than reimplemented per test category — mirrors
/// <see cref="CtapMakeCredentialGetAssertionFixtures"/>'s role for the make-credential/get-assertion surface.
/// </summary>
internal static class CtapClientPinFixtures
{
    /// <summary>
    /// Builds a single-entry <c>get_assertion</c> <c>allowList</c> wrapping <paramref name="credentialIdBytes"/>
    /// as a <see cref="WellKnownPublicKeyCredentialTypes.PublicKey"/> descriptor.
    /// </summary>
    /// <param name="credentialIdBytes">The credential identifier bytes.</param>
    /// <param name="pool">The pool the wrapped <see cref="CredentialId"/> carrier rents from.</param>
    /// <returns>The single-entry allow list.</returns>
    internal static IReadOnlyList<PublicKeyCredentialDescriptor> BuildAllowList(byte[] credentialIdBytes, BaseMemoryPool pool) =>
        [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }];


    /// <summary>
    /// Builds a simulator wired with every shipped CBOR codec, including
    /// <c>authenticatorClientPIN</c>'s request/response codecs — no <c>authenticatorClientPIN</c>
    /// subcommand mints a credential, so no <see cref="CtapCredentialSigningBackend"/> is supplied.
    /// </summary>
    /// <param name="runId">A stable identifier for the simulated authenticator.</param>
    /// <param name="rng">
    /// The random-number backend the AAGUID and every minted credential identifier are drawn from, or
    /// <see langword="null"/> (the default) for <see cref="TestEntropy.NewCounterStream"/>. The PIN/UV
    /// key-agreement key pairs are drawn independently, through the registered production
    /// key-creation seam, regardless of this value.
    /// </param>
    /// <param name="timeProvider">
    /// The simulator's clock, or <see langword="null"/> (the default) to resolve to
    /// <see cref="TestClock.CanonicalEpoch"/> under a fresh <see cref="FakeTimeProvider"/> — the suite's one
    /// instant unless a fixture needs a specific relationship to it — never the system clock.
    /// </param>
    /// <param name="pool">The memory pool the simulator's PIN/UV auth key-agreement material is minted from.</param>
    /// <returns>The composed simulator. The caller owns it and must dispose it.</returns>
    public static CtapAuthenticatorSimulator CreateSimulator(string runId, BaseMemoryPool pool, FillEntropyDelegate? rng = null, TimeProvider? timeProvider = null) =>
        new(
            runId,
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            rng: rng ?? TestEntropy.NewCounterStream(),
            timeProvider: timeProvider ?? new FakeTimeProvider(TestClock.CanonicalEpoch),
            pinUvAuthKeyAgreementPool: pool,
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


    /// <summary>
    /// Builds a custody-composed simulator wired with every shipped CBOR codec, including
    /// <c>authenticatorClientPIN</c>'s request/response codecs, through
    /// <see cref="CtapAuthenticatorSimulator.CreateWithCustodyAsync"/> — the custody counterpart of
    /// <see cref="CreateSimulator"/>, mirroring <see cref="CtapMakeCredentialGetAssertionFixtures.CreateSimulatorWithCustodyAsync"/>'s
    /// own shape for the clientPIN test surface (exercises
    /// <paramref name="pinRetriesCustody"/> against the exact command surface the shipped ClientPIN tests
    /// drive). Unlike <see cref="CreateSimulator"/>, <paramref name="aaguid"/> is REQUIRED (never drawn at
    /// random): a custody-composed simulator's rehydration fingerprint check compares a loaded snapshot's
    /// AAGUID against this value, so a fixture that rebuilds a "second instance" from the same custody
    /// bundle must supply the identical value both times.
    /// </summary>
    /// <param name="runId">The stable identifier for this simulated authenticator and the whole-snapshot custody bundle's own key.</param>
    /// <param name="custody">The whole-snapshot state-custody seam bundle to load from, persist to, and wipe through.</param>
    /// <param name="aaguid">The authenticator-wide AAGUID — REQUIRED, see the summary.</param>
    /// <param name="pinRetriesCustody">
    /// The NV-backed persistent-tier PIN-retries custody seam bundle, or
    /// <see langword="null"/> (the default) to keep <c>PinRetries</c> riding the whole-snapshot cache
    /// — entirely independent of <paramref name="custody"/>.
    /// </param>
    /// <param name="firmwareVersion">The authenticator model's firmware version — part of the rehydration fingerprint alongside <paramref name="aaguid"/>.</param>
    /// <param name="timeProvider">The simulator's clock, or <see langword="null"/> (the default) to resolve to <see cref="TestClock.CanonicalEpoch"/> under a fresh <see cref="FakeTimeProvider"/> — see <see cref="CreateSimulator"/>.</param>
    /// <param name="pool">The memory pool the simulator's PIN/UV auth key-agreement material is minted from.</param>
    /// <param name="rng">
    /// The random-number backend the AAGUID and every minted credential identifier are drawn from, or
    /// <see langword="null"/> (the default) for <see cref="TestEntropy.NewCounterStream"/>.
    /// </param>
    /// <param name="cancellationToken">A cancellation token for the load attempt.</param>
    public static ValueTask<CtapAuthenticatorSimulator> CreateSimulatorWithCustodyAsync(
        string runId, CtapStateCustody custody, Guid aaguid, BaseMemoryPool pool, CtapPinRetriesCustody? pinRetriesCustody = null, int firmwareVersion = 1,
        TimeProvider? timeProvider = null, FillEntropyDelegate? rng = null, CancellationToken cancellationToken = default) =>
        CtapAuthenticatorSimulator.CreateWithCustodyAsync(
            runId,
            custody,
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
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
            encodeGetAssertionExtensionOutputs: CtapGetAssertionExtensionOutputsCborWriter.Write,
            timeProvider: timeProvider ?? new FakeTimeProvider(TestClock.CanonicalEpoch),
            pinUvAuthKeyAgreementPool: pool,
            rng: rng ?? TestEntropy.NewCounterStream(),
            aaguid: aaguid,
            firmwareVersion: firmwareVersion,
            pinRetriesCustody: pinRetriesCustody,
            cancellationToken: cancellationToken);
}
