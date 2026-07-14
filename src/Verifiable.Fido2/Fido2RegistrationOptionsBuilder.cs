using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// Builds <see cref="PublicKeyCredentialCreationOptions"/> using a fold/aggregate pattern with
/// sensible, spec-derived defaults.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-createCredential">W3C Web Authentication Level
/// 3, section 5.4: Options for Credential Creation</see>. Mirrors <c>KeyDidBuilder</c>'s shape: this
/// constructor registers the default transformations every registration-options document needs, and
/// <see cref="BuildAsync"/> precomputes a <see cref="Fido2RegistrationOptionsBuildState"/> from its
/// own parameters before invoking the base fold. A caller may register additional transformations via
/// the inherited <c>With</c> — for example to append algorithms beyond the default
/// <see cref="PublicKeyCredentialCreationOptions.PubKeyCredParams"/> list, since those run after the
/// defaults registered here.
/// </para>
/// <para>
/// See <see cref="PublicKeyCredentialCreationOptions"/>'s own member remarks for exactly which SHOULD
/// each default transformation satisfies, and for the five named extension-input carve-outs this
/// type ships (the generic <c>extensions</c> client-input member remains out of scope).
/// </para>
/// </remarks>
/// <example>
/// <code>
/// var builder = new Fido2RegistrationOptionsBuilder();
/// var options = await builder.BuildAsync(
///     rpId: "example.com",
///     rpName: null,
///     userId: userHandle,
///     userName: "alexm",
///     userDisplayName: "Alex Müller",
///     pool: BaseMemoryPool.Shared,
///     existingCredentials: storedCredentials,
///     cancellationToken: cancellationToken);
/// </code>
/// </example>
public sealed class Fido2RegistrationOptionsBuilder: Builder<PublicKeyCredentialCreationOptions, Fido2RegistrationOptionsBuildState, Fido2RegistrationOptionsBuilder>
{
    /// <summary>
    /// The default <c>pubKeyCredParams</c> list: EdDSA, ES256, RS256 in that preference order (row
    /// 3497). Never the RFC9864 fully-specified identifiers (row 3506) — satisfied by construction,
    /// since those constants are simply never added here.
    /// </summary>
    private static IReadOnlyList<PublicKeyCredentialParameters> DefaultPubKeyCredParams { get; } =
    [
        new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.EdDsa },
        new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Es256 },
        new PublicKeyCredentialParameters { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Alg = WellKnownCoseAlgorithms.Rs256 }
    ];


    /// <summary>
    /// Initializes a new instance with the default registration-options transformations registered.
    /// </summary>
    public Fido2RegistrationOptionsBuilder()
    {
        //First transformation: assemble the rp and user entities.
        _ = With((options, builder, state) =>
        {
            options.Rp = new PublicKeyCredentialRpEntity
            {
                Id = state!.RpId,
                Name = state.RpName ?? state.RpId
            };
            options.User = new PublicKeyCredentialUserEntity
            {
                Id = state.UserId,
                Name = state.UserName,
                DisplayName = state.UserDisplayName ?? string.Empty
            };

            return ValueTask.FromResult(options);
        })
        //Second transformation: the challenge, via the wave-4 entropy seam unless the caller supplied one.
        .With((options, builder, state) =>
        {
            options.Challenge = state!.Challenge ?? Fido2ChallengeGeneration.Generate(state.Pool);

            return ValueTask.FromResult(options);
        })
        //Third transformation: the default pubKeyCredParams list (rows 3497/3506).
        .With((options, builder, state) =>
        {
            options.PubKeyCredParams = DefaultPubKeyCredParams;

            return ValueTask.FromResult(options);
        })
        //Fourth transformation: excludeCredentials, projected from existing credential records (rows 3527/4270/4277/4285).
        .With((options, builder, state) =>
        {
            options.ExcludeCredentials = Fido2OptionsDescriptors.ProjectDescriptors(state!.ExistingCredentials);

            return ValueTask.FromResult(options);
        })
        //Fifth transformation: authenticatorSelection, keeping residentKey/requireResidentKey consistent
        //in both directions (CR line 4831 and row 3731) and defaulting userVerification to Preferred.
        .With((options, builder, state) =>
        {
            ResidentKeyRequirement residentKey = state!.ResidentKey
                ?? (state.RequireResidentKey == true ? ResidentKeyRequirement.Required : ResidentKeyRequirement.Discouraged);
            bool requireResidentKey = state.RequireResidentKey ?? (residentKey == ResidentKeyRequirement.Required);

            options.AuthenticatorSelection = new AuthenticatorSelectionCriteria
            {
                AuthenticatorAttachment = state.AuthenticatorAttachment,
                ResidentKey = residentKey,
                RequireResidentKey = requireResidentKey,
                UserVerification = state.UserVerification ?? UserVerificationRequirement.Preferred
            };

            return ValueTask.FromResult(options);
        })
        //Sixth transformation: hints, and row 4470's authenticatorAttachment compatibility mapping —
        //"if two hints are contradictory, the first one controls" (CR section 5.8.8), applied only
        //when the caller has not already set an explicit attachment.
        .With((options, builder, state) =>
        {
            IReadOnlyList<PublicKeyCredentialHint> hints = state!.Hints ?? [];
            options.Hints = hints;

            if(hints.Count > 0 && options.AuthenticatorSelection?.AuthenticatorAttachment is null)
            {
                string compatibilityAttachment = WellKnownPublicKeyCredentialHints.ToCompatibilityAuthenticatorAttachment(hints[0]);
                options.AuthenticatorSelection = options.AuthenticatorSelection! with { AuthenticatorAttachment = compatibilityAttachment };
            }

            return ValueTask.FromResult(options);
        })
        //Seventh transformation: attestation preference and format list, matching the CR's own defaults.
        .With((options, builder, state) =>
        {
            options.Attestation = state!.Attestation ?? AttestationConveyancePreference.None;
            options.AttestationFormats = state.AttestationFormats ?? [];

            return ValueTask.FromResult(options);
        })
        //Eighth transformation: timeout — pass-through only, no spec-mandated default exists.
        .With((options, builder, state) =>
        {
            options.Timeout = state!.Timeout;

            return ValueTask.FromResult(options);
        })
        //Ninth transformation: the two registration-side named extension-input carve-outs.
        .With((options, builder, state) =>
        {
            options.AppIdExclude = state!.AppIdExclude;
            options.LargeBlob = state.LargeBlobSupport is LargeBlobSupport support
                ? new Fido2LargeBlobRegistrationExtensionInput { Support = support }
                : null;

            return ValueTask.FromResult(options);
        });
    }


    /// <summary>
    /// Builds a <see cref="PublicKeyCredentialCreationOptions"/> document from the provided
    /// parameters.
    /// </summary>
    /// <param name="rpId">The relying party identifier. See <see cref="PublicKeyCredentialRpEntity.Id"/>.</param>
    /// <param name="rpName">The relying party's display name, or <see langword="null"/> to default to <paramref name="rpId"/> (row 3588).</param>
    /// <param name="userId">The user handle. Borrowed — this builder does not take ownership or dispose it.</param>
    /// <param name="userName">The user account's name.</param>
    /// <param name="userDisplayName">The user account's display name, or <see langword="null"/> to default to an empty string (row 3677).</param>
    /// <param name="pool">The memory pool the default challenge transformation rents entropy from.</param>
    /// <param name="existingCredentials">Existing credentials mapped to this user account, projected into <c>excludeCredentials</c>, or <see langword="null"/> for none.</param>
    /// <param name="challenge">An explicit challenge overriding the default entropy-provider-generated one, or <see langword="null"/> to use the default.</param>
    /// <param name="timeout">The <c>timeout</c> hint, or <see langword="null"/> to leave it unset.</param>
    /// <param name="attestation">The attestation conveyance preference, or <see langword="null"/> to default to <see cref="AttestationConveyancePreference.None"/>.</param>
    /// <param name="attestationFormats">The preferred attestation statement formats, or <see langword="null"/> for no preference.</param>
    /// <param name="authenticatorAttachment">An explicit authenticator attachment filter, or <see langword="null"/> for any modality (subject to the row-4470 hint compatibility mapping).</param>
    /// <param name="residentKey">The resident-key requirement, or <see langword="null"/> to derive it from <paramref name="requireResidentKey"/>.</param>
    /// <param name="requireResidentKey">The Level 1 compatibility flag, or <see langword="null"/> to derive it from <paramref name="residentKey"/>.</param>
    /// <param name="userVerification">The user verification requirement, or <see langword="null"/> to default to <see cref="UserVerificationRequirement.Preferred"/>.</param>
    /// <param name="hints">Hints for the user agent, or <see langword="null"/> for none.</param>
    /// <param name="appIdExclude">The <c>appidExclude</c> extension's legacy AppID, or <see langword="null"/> when not requested.</param>
    /// <param name="largeBlobSupport">The <c>largeBlob</c> extension's registration-side support requirement, or <see langword="null"/> when not requested.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A <see cref="ValueTask{PublicKeyCredentialCreationOptions}"/> containing the fully constructed options document.</returns>
    /// <exception cref="System.ArgumentException"><paramref name="rpId"/> or <paramref name="userName"/> is null, empty, or whitespace.</exception>
    /// <exception cref="System.ArgumentNullException"><paramref name="userId"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public ValueTask<PublicKeyCredentialCreationOptions> BuildAsync(
        string rpId,
        string? rpName,
        UserHandle userId,
        string userName,
        string? userDisplayName,
        MemoryPool<byte> pool,
        IReadOnlyList<Fido2CredentialRecord>? existingCredentials = null,
        string? challenge = null,
        uint? timeout = null,
        AttestationConveyancePreference? attestation = null,
        IReadOnlyList<string>? attestationFormats = null,
        string? authenticatorAttachment = null,
        ResidentKeyRequirement? residentKey = null,
        bool? requireResidentKey = null,
        UserVerificationRequirement? userVerification = null,
        IReadOnlyList<PublicKeyCredentialHint>? hints = null,
        string? appIdExclude = null,
        LargeBlobSupport? largeBlobSupport = null,
        CancellationToken cancellationToken = default)
    {
        System.ArgumentException.ThrowIfNullOrWhiteSpace(rpId);
        System.ArgumentNullException.ThrowIfNull(userId);
        System.ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        System.ArgumentNullException.ThrowIfNull(pool);

        Fido2RegistrationOptionsBuildState state = new()
        {
            RpId = rpId,
            RpName = rpName,
            UserId = userId,
            UserName = userName,
            UserDisplayName = userDisplayName,
            Pool = pool,
            ExistingCredentials = existingCredentials,
            Challenge = challenge,
            Timeout = timeout,
            Attestation = attestation,
            AttestationFormats = attestationFormats,
            AuthenticatorAttachment = authenticatorAttachment,
            ResidentKey = residentKey,
            RequireResidentKey = requireResidentKey,
            UserVerification = userVerification,
            Hints = hints,
            AppIdExclude = appIdExclude,
            LargeBlobSupport = largeBlobSupport
        };

        return BuildAsync(
            param: state,
            preBuildActionAsync: (s, _) => ValueTask.FromResult(s),
            cancellationToken: cancellationToken);
    }
}
