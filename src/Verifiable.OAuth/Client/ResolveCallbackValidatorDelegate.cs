using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Resolves the callback validation rule set for a registration by
/// dispatching on its <see cref="ClientRegistration.Profile"/>. Used by
/// callback-handling protocol methods (the AuthCode callback handler and
/// any future protocol method that consumes redirect parameters) to obtain
/// the <see cref="ClaimIssuer{TInput}"/> that asserts the per-rule claims
/// the callback context must satisfy.
/// </summary>
/// <remarks>
/// <para>
/// The library's default implementation is
/// <see cref="ClientPolicyProfiles.DefaultResolveCallbackValidator"/>. It
/// dispatches across the three shipped <see cref="PolicyProfile"/> values
/// and selects the underlying <see cref="ValidationProfiles"/> rule set
/// accordingly:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <see cref="PolicyProfile.Fapi20"/> →
///     <see cref="ValidationProfiles.CallbackHaip10Rules"/> with issuer
///     label <c>callback-fapi20</c>. (The callback rule set for FAPI 2.0 and
///     HAIP 1.0 currently coincide; the labels differ so audit and
///     diagnostics distinguish them.)
///   </description></item>
///   <item><description>
///     <see cref="PolicyProfile.Haip10"/> →
///     <see cref="ValidationProfiles.CallbackHaip10Rules"/> with issuer
///     label <c>callback-haip10</c>.
///   </description></item>
///   <item><description>
///     <see cref="PolicyProfile.Rfc6749WithPkce"/> →
///     <see cref="ValidationProfiles.CallbackRfc6749WithPkceRules"/> with
///     issuer label <c>callback-rfc6749-pkce</c>.
///   </description></item>
/// </list>
/// <para>
/// Applications with bespoke callback rules supply a custom delegate on
/// <see cref="OAuthClientInfrastructure.ResolveCallbackValidator"/>; the
/// custom implementation typically falls through to the library default for
/// codes it does not own.
/// </para>
/// </remarks>
/// <param name="registration">The registration whose callback validator is being resolved.</param>
/// <param name="timeProvider">The time source the resolved <see cref="ClaimIssuer{TInput}"/> binds to.</param>
public delegate ClaimIssuer<ValidationContext> ResolveCallbackValidatorDelegate(
    ClientRegistration registration,
    TimeProvider timeProvider);
