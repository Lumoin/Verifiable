using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2;

/// <summary>
/// Builds <see cref="PublicKeyCredentialRequestOptions"/> using a fold/aggregate pattern with
/// sensible, spec-derived defaults.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-getAssertion">W3C Web Authentication Level 3,
/// section 5.5: Options for Assertion Generation</see>. Mirrors
/// <see cref="Fido2RegistrationOptionsBuilder"/>'s shape and reasoning — see that type's remarks. See
/// <see cref="PublicKeyCredentialRequestOptions"/>'s own member remarks for exactly which SHOULD each
/// default transformation satisfies.
/// </remarks>
/// <example>
/// <code>
/// var builder = new Fido2AssertionOptionsBuilder();
/// var options = await builder.BuildAsync(
///     rpId: "example.com",
///     pool: BaseMemoryPool.Shared,
///     allowedCredentials: storedCredentials,
///     cancellationToken: cancellationToken);
/// </code>
/// </example>
public sealed class Fido2AssertionOptionsBuilder: Builder<PublicKeyCredentialRequestOptions, Fido2AssertionOptionsBuildState, Fido2AssertionOptionsBuilder>
{
    /// <summary>
    /// Initializes a new instance with the default request-options transformations registered.
    /// </summary>
    public Fido2AssertionOptionsBuilder()
    {
        //First transformation: the relying party identifier.
        _ = With((options, builder, state) =>
        {
            options.RpId = state!.RpId;

            return ValueTask.FromResult(options);
        })
        //Second transformation: the challenge, via the wave-4 entropy seam unless the caller supplied one.
        .With((options, builder, state) =>
        {
            options.Challenge = state!.Challenge ?? Fido2ChallengeGeneration.Generate(state.Pool);

            return ValueTask.FromResult(options);
        })
        //Third transformation: allowCredentials, projected from allowed credential records (rows 3902/3906/4270/4277/4285),
        //empty (the discoverable-credential path, row 3914) when none are supplied.
        .With((options, builder, state) =>
        {
            options.AllowCredentials = Fido2OptionsDescriptors.ProjectDescriptors(state!.AllowedCredentials);

            return ValueTask.FromResult(options);
        })
        //Fourth transformation: user verification, defaulting to Preferred per the CR's own IDL default.
        .With((options, builder, state) =>
        {
            options.UserVerification = state!.UserVerification ?? UserVerificationRequirement.Preferred;

            return ValueTask.FromResult(options);
        })
        //Fifth transformation: hints. Unlike creation options, request options carry no
        //authenticatorAttachment for the row-4470 compatibility mapping to set.
        .With((options, builder, state) =>
        {
            options.Hints = state!.Hints ?? [];

            return ValueTask.FromResult(options);
        })
        //Sixth transformation: timeout — pass-through only, no spec-mandated default exists.
        .With((options, builder, state) =>
        {
            options.Timeout = state!.Timeout;

            return ValueTask.FromResult(options);
        })
        //Seventh transformation: the two assertion-side named extension-input carve-outs.
        .With((options, builder, state) =>
        {
            options.AppId = state!.AppId;
            options.LargeBlob = state.LargeBlob;

            return ValueTask.FromResult(options);
        });
    }


    /// <summary>
    /// Builds a <see cref="PublicKeyCredentialRequestOptions"/> document from the provided
    /// parameters.
    /// </summary>
    /// <param name="rpId">The relying party identifier this assertion is scoped to.</param>
    /// <param name="pool">The memory pool the default challenge transformation rents entropy from.</param>
    /// <param name="allowedCredentials">Credentials acceptable for this assertion, projected into <c>allowCredentials</c>, or <see langword="null"/> for the discoverable-credential path.</param>
    /// <param name="challenge">An explicit challenge overriding the default entropy-provider-generated one, or <see langword="null"/> to use the default.</param>
    /// <param name="timeout">The <c>timeout</c> hint, or <see langword="null"/> to leave it unset.</param>
    /// <param name="userVerification">The user verification requirement, or <see langword="null"/> to default to <see cref="UserVerificationRequirement.Preferred"/>.</param>
    /// <param name="hints">Hints for the user agent, or <see langword="null"/> for none.</param>
    /// <param name="appId">The <c>appid</c> extension's legacy AppID, or <see langword="null"/> when not requested.</param>
    /// <param name="largeBlob">The <c>largeBlob</c> extension's assertion-side input (a read or a write request), or <see langword="null"/> when not requested.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A <see cref="ValueTask{PublicKeyCredentialRequestOptions}"/> containing the fully constructed options document.</returns>
    /// <exception cref="System.ArgumentException"><paramref name="rpId"/> is null, empty, or whitespace.</exception>
    /// <exception cref="System.ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public ValueTask<PublicKeyCredentialRequestOptions> BuildAsync(
        string rpId,
        MemoryPool<byte> pool,
        IReadOnlyList<Fido2CredentialRecord>? allowedCredentials = null,
        string? challenge = null,
        uint? timeout = null,
        UserVerificationRequirement? userVerification = null,
        IReadOnlyList<PublicKeyCredentialHint>? hints = null,
        string? appId = null,
        Fido2LargeBlobAssertionExtensionInput? largeBlob = null,
        CancellationToken cancellationToken = default)
    {
        System.ArgumentException.ThrowIfNullOrWhiteSpace(rpId);
        System.ArgumentNullException.ThrowIfNull(pool);

        Fido2AssertionOptionsBuildState state = new()
        {
            RpId = rpId,
            Pool = pool,
            AllowedCredentials = allowedCredentials,
            Challenge = challenge,
            Timeout = timeout,
            UserVerification = userVerification,
            Hints = hints,
            AppId = appId,
            LargeBlob = largeBlob
        };

        return BuildAsync(
            param: state,
            preBuildActionAsync: (s, _) => ValueTask.FromResult(s),
            cancellationToken: cancellationToken);
    }
}
