using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared fixtures for the CTAP wave-2 capstone flow tests: the RP/client-side plumbing the capstone
/// needs on top of <see cref="CtapWave2AuthenticatorFixtures"/> — the independently-computed
/// <c>rpIdHash</c> a real relying party would compute itself, and the
/// WebAuthn-creation-options-to-CTAP-request translation a real platform performs before ever handing a
/// request to <see cref="CtapAuthenticatorMakeCredentialClient"/>/<see cref="CtapAuthenticatorGetAssertionClient"/>.
/// <c>clientDataJSON</c> authoring lives in <see cref="WebAuthnClientDataFixtures"/>.
/// </summary>
internal static class CtapWave2CapstoneFixtures
{
    /// <summary>The SHA-256 digest length in bytes, used to size an independently computed <c>rpIdHash</c>.</summary>
    private const int Sha256Length = 32;


    /// <summary>
    /// Independently computes the SHA-256 <c>rpIdHash</c> of <paramref name="rpId"/>'s UTF-8 bytes — the
    /// same computation a real relying party performs on its own, through the same production digest
    /// seam the authenticator simulator uses internally, but never reading the simulator's own state.
    /// </summary>
    public static DigestValue ComputeExpectedRpIdHash(string rpId, MemoryPool<byte> pool)
    {
        byte[] rpIdBytes = Encoding.UTF8.GetBytes(rpId);

        return CryptographicKeyEvents.ComputeDigest(rpIdBytes, Sha256Length, CryptoTags.Sha256Digest, pool);
    }


    /// <summary>
    /// Translates a WebAuthn <see cref="PublicKeyCredentialCreationOptions"/> document into the
    /// <see cref="CtapMakeCredentialRequest"/> a CTAP platform binding sends on the wire — the
    /// client-side translation a real platform performs, mirrored here since it is not part of this
    /// wave's shipped production surface (only the reverse, response-side translation is).
    /// </summary>
    /// <param name="options">The creation options a relying party issued.</param>
    /// <param name="clientDataHash">The computed <c>clientDataHash</c> for this ceremony.</param>
    /// <param name="pool">The memory pool the request's user handle rents from.</param>
    /// <param name="attestationFormatsPreference">The client/RP's prioritized attestation statement format preference, or <see langword="null"/> for none.</param>
    /// <param name="pinUvAuthParam">
    /// A pre-computed <c>pinUvAuthParam</c> covering <paramref name="clientDataHash"/> alone, or
    /// <see langword="null"/> to send no PIN/UV auth token at all — the wave-5c PIN/UV token leg a real
    /// platform adds once it has established a <c>pinUvAuthToken</c>.
    /// </param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol <paramref name="pinUvAuthParam"/> was computed under, or <see langword="null"/> when <paramref name="pinUvAuthParam"/> is <see langword="null"/>.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the user handle carrier transfers to the returned CtapMakeCredentialRequest, which the caller disposes along with the rest of the request's carriers.")]
    public static CtapMakeCredentialRequest BuildMakeCredentialRequest(
        PublicKeyCredentialCreationOptions options,
        DigestValue clientDataHash,
        MemoryPool<byte> pool,
        IReadOnlyList<string>? attestationFormatsPreference = null,
        ReadOnlyMemory<byte>? pinUvAuthParam = null,
        int? pinUvAuthProtocol = null)
    {
        UserHandle userHandle = UserHandle.Create(options.User!.Id.AsReadOnlySpan(), pool);
        bool residentKey = options.AuthenticatorSelection?.ResidentKey == ResidentKeyRequirement.Required;

        //CTAP 2.3 forbids an empty excludeList: a platform omits the member entirely rather than
        //sending a present-but-empty array, mirroring PublicKeyCredentialCreationOptions.ExcludeCredentials'
        //own "[] when none supplied" default.
        IReadOnlyList<PublicKeyCredentialDescriptor>? excludeList = options.ExcludeCredentials is { Count: > 0 } excludeCredentials
            ? excludeCredentials
            : null;

        return new CtapMakeCredentialRequest(
            clientDataHash,
            new CtapPublicKeyCredentialRpEntity(options.Rp!.Id!, options.Rp.Name),
            new CtapPublicKeyCredentialUserEntity(userHandle, options.User.Name, options.User.DisplayName),
            options.PubKeyCredParams!,
            excludeList,
            Extensions: null,
            Options: new CtapCommandOptions(ResidentKey: residentKey),
            PinUvAuthParam: pinUvAuthParam,
            PinUvAuthProtocol: pinUvAuthProtocol,
            AttestationFormatsPreference: attestationFormatsPreference);
    }


    /// <summary>
    /// Translates a WebAuthn <see cref="PublicKeyCredentialRequestOptions"/> document into the
    /// <see cref="CtapGetAssertionRequest"/> a CTAP platform binding sends on the wire — the
    /// client-side translation a real platform performs, mirrored here for the same reason as
    /// <see cref="BuildMakeCredentialRequest"/>. Never sends an <c>rk</c> option key, per CTAP 2.3
    /// section 6.2's prohibition.
    /// </summary>
    /// <param name="options">The request options a relying party issued.</param>
    /// <param name="clientDataHash">The computed <c>clientDataHash</c> for this ceremony.</param>
    /// <param name="pinUvAuthParam">
    /// A pre-computed <c>pinUvAuthParam</c> covering <paramref name="clientDataHash"/> alone, or
    /// <see langword="null"/> to send no PIN/UV auth token at all — the wave-5c PIN/UV token leg a real
    /// platform adds once it has established a <c>pinUvAuthToken</c>.
    /// </param>
    /// <param name="pinUvAuthProtocol">The PIN/UV auth protocol <paramref name="pinUvAuthParam"/> was computed under, or <see langword="null"/> when <paramref name="pinUvAuthParam"/> is <see langword="null"/>.</param>
    public static CtapGetAssertionRequest BuildGetAssertionRequest(
        PublicKeyCredentialRequestOptions options, DigestValue clientDataHash, ReadOnlyMemory<byte>? pinUvAuthParam = null, int? pinUvAuthProtocol = null)
    {
        //CTAP 2.3 forbids an empty allowList: a platform omits the member entirely (the
        //discoverable-credential path) rather than sending a present-but-empty array, mirroring
        //PublicKeyCredentialRequestOptions.AllowCredentials' own "[] when none supplied" default.
        IReadOnlyList<PublicKeyCredentialDescriptor>? allowList = options.AllowCredentials is { Count: > 0 } allowCredentials
            ? allowCredentials
            : null;

        return new CtapGetAssertionRequest(options.RpId!, clientDataHash, allowList, PinUvAuthParam: pinUvAuthParam, PinUvAuthProtocol: pinUvAuthProtocol);
    }
}
