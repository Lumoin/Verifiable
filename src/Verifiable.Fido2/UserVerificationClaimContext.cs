using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.Fido2;

/// <summary>
/// <see cref="ClaimContext"/> subtype recording the <c>UV</c> flag state a
/// <see cref="Fido2RegistrationChecks.CheckRegistrationUserVerified"/>/
/// <see cref="Fido2AssertionChecks.CheckAssertionUserVerified"/> claim observed, for the two
/// <see cref="UserVerificationRequirement"/> policies (<c>Preferred</c>, <c>Discouraged</c>) that
/// succeed regardless of the bit's value.
/// </summary>
/// <param name="UserVerified">
/// The <c>UV</c> flag value the ceremony's <c>authData</c> carried, per
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement">W3C Web
/// Authentication Level 3, section 5.8.6: User Verification Requirement Enumeration</see>'s
/// <c>preferred</c>/<c>discouraged</c> descriptions, both of which leave the relying party free to
/// observe — without enforcing — the state.
/// </param>
/// <remarks>
/// Not attached under <see cref="UserVerificationRequirement.Required"/>: that policy's claim
/// carries no context (<see cref="ClaimContext.None"/>) since a <see langword="false"/> outcome
/// already tells the caller everything the flag would; observing it separately would be redundant.
/// </remarks>
[DebuggerDisplay("UserVerificationClaimContext(UserVerified={UserVerified})")]
public sealed record UserVerificationClaimContext(bool UserVerified): ClaimContext;
