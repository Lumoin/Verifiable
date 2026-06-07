namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The per-location context handed to a <see cref="DecoyDigestCountDelegate"/> so the issuer's
/// policy can decide how many decoy digests to add based on where it is and what is already there.
/// </summary>
/// <remarks>
/// <para>
/// The delegate is invoked once for each <c>_sd</c> / <c>redacted_claim_keys</c> location during
/// redaction. This context describes that location; combined with whatever the issuer already knows
/// at the call site by closure (the credential being issued and the disclosable paths it chose), it
/// lets a policy be both schema-aware and structure-aware. For example, padding every location to a
/// uniform bucket size — the canonical unlinkability strategy — is
/// <c>ctx =&gt; Math.Max(0, bucket - ctx.RealDisclosureCount)</c>.
/// </para>
/// </remarks>
/// <param name="Location">
/// The <see cref="CredentialPath"/> of the object whose <c>_sd</c> array is being padded
/// (<see cref="CredentialPath.Root"/> for the top level).
/// </param>
/// <param name="RealDisclosureCount">
/// The number of real (non-decoy) disclosure digests already at this location. This is the count an
/// adversarial verifier would otherwise see, so it is the natural input for count-flattening policies.
/// </param>
/// <param name="State">
/// The per-call data the caller supplied via <see cref="DecoyDigestOptions.State"/>, threaded through
/// unchanged. The library does not interpret it; the policy casts it back to whatever it passed in (a
/// request/tenant/user object, a dictionary, etc.). <see langword="null"/> when none was supplied.
/// </param>
public sealed record DecoyDigestContext(CredentialPath Location, int RealDisclosureCount, object? State = null);
