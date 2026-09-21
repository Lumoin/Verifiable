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
            options.RpId = state.RpId;

            return ValueTask.FromResult(options);
        })
        //Second transformation: the challenge, via the entropy seam unless the caller supplied one.
        .With((options, builder, state) =>
        {
            options.Challenge = state.Challenge ?? Fido2ChallengeGeneration.Generate(state.Pool);

            return ValueTask.FromResult(options);
        })
        //Third transformation: allowCredentials, projected from allowed credential records (rows 3902/3906/4270/4277/4285),
        //empty (the discoverable-credential path, row 3914) when none are supplied.
        .With((options, builder, state) =>
        {
            options.AllowCredentials = Fido2OptionsDescriptors.ProjectDescriptors(state.AllowedCredentials);

            return ValueTask.FromResult(options);
        })
        //Fourth transformation: user verification, defaulting to Preferred per the CR's own IDL default.
        .With((options, builder, state) =>
        {
            options.UserVerification = state.UserVerification ?? UserVerificationRequirement.Preferred;

            return ValueTask.FromResult(options);
        })
        //Fifth transformation: hints. Unlike creation options, request options carry no
        //authenticatorAttachment for the row-4470 compatibility mapping to set.
        .With((options, builder, state) =>
        {
            options.Hints = state.Hints ?? [];

            return ValueTask.FromResult(options);
        })
        //Sixth transformation: timeout — pass-through only, no spec-mandated default exists.
        .With((options, builder, state) =>
        {
            options.Timeout = state.Timeout;

            return ValueTask.FromResult(options);
        })
        //Seventh transformation: the appid/largeBlob assertion-side named extension-input carve-outs.
        .With((options, builder, state) =>
        {
            options.AppId = state.AppId;
            options.LargeBlob = state.LargeBlob;

            return ValueTask.FromResult(options);
        })
        //Eighth transformation: the prf carve-out, checked against allowCredentials (already
        //assembled by the third transformation above) per section 10.1.4's own authentication
        //processing algorithm — see CheckPrf's remarks.
        .With((options, builder, state) =>
        {
            CheckPrf(state.Prf, options.AllowCredentials);
            options.Prf = state.Prf;

            return ValueTask.FromResult(options);
        });
    }


    /// <summary>
    /// Refuses a <c>prf</c> input whose <see cref="Fido2PrfAssertionExtensionInput.EvalByCredential"/>
    /// a conforming client would refuse, applying the two conditions of
    /// <see href="https://www.w3.org/TR/webauthn-3/#prf-extension">Web Authentication Level 3,
    /// section 10.1.4</see> that this builder can check before any client does: "If
    /// evalByCredential is not empty but allowCredentials is empty, return a DOMException whose
    /// name is “NotSupportedError”", and a key that "does not equal the id of some element of
    /// allowCredentials" is a “SyntaxError”.
    /// </summary>
    /// <remarks>
    /// The input comes from the relying party's own code, so a violation is the caller's defect
    /// and is reported the way this builder reports its other invalid arguments. Dropping the
    /// input instead would leave the relying party waiting for a per-credential result no client
    /// will ever produce.
    /// </remarks>
    /// <param name="prf">The caller-supplied <c>prf</c> input, or <see langword="null"/> when not requested.</param>
    /// <param name="allowCredentials">The assembled <c>allowCredentials</c> list.</param>
    /// <exception cref="System.ArgumentException">
    /// <paramref name="prf"/> carries <c>evalByCredential</c> entries while
    /// <paramref name="allowCredentials"/> is empty, or an entry's key names no element of
    /// <paramref name="allowCredentials"/>.
    /// </exception>
    private static void CheckPrf(
        Fido2PrfAssertionExtensionInput? prf,
        IReadOnlyList<PublicKeyCredentialDescriptor>? allowCredentials)
    {
        if(prf?.EvalByCredential is not { Count: > 0 } evalByCredential)
        {
            return;
        }

        if(allowCredentials is not { Count: > 0 })
        {
            throw new System.ArgumentException(
                "The prf input carries evalByCredential entries while allowCredentials is empty.", nameof(prf));
        }

        foreach(CredentialId credentialId in evalByCredential.Keys)
        {
            bool isAllowedCredential = false;
            foreach(PublicKeyCredentialDescriptor descriptor in allowCredentials)
            {
                if(credentialId.Equals(descriptor.Id))
                {
                    isAllowedCredential = true;
                    break;
                }
            }

            if(!isAllowedCredential)
            {
                throw new System.ArgumentException(
                    "A prf evalByCredential key names no element of allowCredentials.", nameof(prf));
            }
        }
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
    /// <param name="prf">The <c>prf</c> extension's assertion-side input, or <see langword="null"/> when not requested.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A <see cref="ValueTask{PublicKeyCredentialRequestOptions}"/> containing the fully constructed options document.</returns>
    /// <exception cref="System.ArgumentException"><paramref name="rpId"/> is null, empty, or whitespace.</exception>
    /// <exception cref="System.ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public ValueTask<PublicKeyCredentialRequestOptions> BuildAsync(
        string rpId,
        BaseMemoryPool pool,
        IReadOnlyList<Fido2CredentialRecord>? allowedCredentials = null,
        string? challenge = null,
        uint? timeout = null,
        UserVerificationRequirement? userVerification = null,
        IReadOnlyList<PublicKeyCredentialHint>? hints = null,
        string? appId = null,
        Fido2LargeBlobAssertionExtensionInput? largeBlob = null,
        Fido2PrfAssertionExtensionInput? prf = null,
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
            LargeBlob = largeBlob,
            Prf = prf
        };

        return BuildAsync(
            param: state,
            preBuildActionAsync: (s, _) => ValueTask.FromResult(s),
            cancellationToken: cancellationToken);
    }
}
