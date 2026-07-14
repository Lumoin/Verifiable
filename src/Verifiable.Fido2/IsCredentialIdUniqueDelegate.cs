namespace Verifiable.Fido2;

/// <summary>
/// Checks whether a credential identifier is not yet registered to any user — a relying-party
/// storage lookup this library cannot perform itself.
/// </summary>
/// <param name="credentialId">The candidate <c>credentialId</c> from the attested credential data.</param>
/// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
/// <returns>
/// A <see cref="ValueTask{TResult}"/> resolving to <see langword="true"/> when
/// <paramref name="credentialId"/> is not registered to any user; <see langword="false"/> when it
/// is already registered to some user.
/// </returns>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web
/// Authentication Level 3, section 7.1: Registering a New Credential</see>, step 26: "Verify that
/// the credentialId is not yet registered for any user. If the credentialId is already known then
/// the RP SHOULD fail this registration ceremony." This is an RP-supplied seam because only the
/// relying party's own credential storage can answer it; <see cref="Fido2RegistrationVerifier"/>
/// calls it but does not implement it.
/// </remarks>
public delegate ValueTask<bool> IsCredentialIdUniqueDelegate(CredentialId credentialId, CancellationToken cancellationToken);
