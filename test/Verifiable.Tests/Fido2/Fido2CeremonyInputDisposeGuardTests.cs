using Verifiable.Fido2;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests that <see cref="RegistrationCeremonyInput.Dispose"/> and
/// <see cref="AssertionCeremonyInput.Dispose"/> tolerate being called more than once.
/// </summary>
/// <remarks>
/// Both records guard their <c>Dispose()</c> body with an <c>if(disposed) return;</c> check before
/// releasing every owned carrier (<see cref="Fido2.AuthenticatorData"/>,
/// <see cref="RegistrationCeremonyInput.ExpectedRpIdHash"/>/<see cref="AssertionCeremonyInput.ExpectedRpIdHash"/>,
/// and — for an assertion — <see cref="AssertionCeremonyInput.CredentialId"/>, every
/// <see cref="AssertionCeremonyInput.AllowedCredentialIds"/> entry,
/// <see cref="AssertionCeremonyInput.ResponseUserHandle"/>,
/// <see cref="AssertionCeremonyInput.StoredUserHandle"/>, and
/// <see cref="AssertionCeremonyInput.ExpectedAppIdHash"/>). Every other test in this suite disposes
/// its ceremony input exactly once via a <see langword="using"/> declaration, so removing that guard
/// — which would re-release every owned carrier on a second call — would pass unnoticed anywhere
/// else in the suite.
/// </remarks>
[TestClass]
internal sealed class Fido2CeremonyInputDisposeGuardTests
{
    /// <summary><see cref="RegistrationCeremonyInput.Dispose"/> called twice does not throw.</summary>
    [TestMethod]
    public void RegistrationCeremonyInputDoubleDisposeDoesNotThrow()
    {
        RegistrationCeremonyInput input = Fido2CeremonyInputFactory.CreateValidRegistrationInput();

        input.Dispose();
        input.Dispose();
    }


    /// <summary><see cref="AssertionCeremonyInput.Dispose"/> called twice does not throw.</summary>
    [TestMethod]
    public void AssertionCeremonyInputDoubleDisposeDoesNotThrow()
    {
        AssertionCeremonyInput input = Fido2CeremonyInputFactory.CreateValidAssertionInput();

        input.Dispose();
        input.Dispose();
    }
}
