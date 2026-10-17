using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The choice of an ID-JAG mint's subject (<see cref="IdJagSubjectTokenSelection.Select"/>): the ID Token while it has not run
/// out, the refresh token where the preference names it and one is held, and none otherwise.
/// </summary>
[TestClass]
internal sealed class IdJagSubjectTokenSelectionTests
{
    /// <summary>The instant every row selects at.</summary>
    private static DateTimeOffset Now { get; } = TestClock.CanonicalEpoch;


    /// <summary>The ID Token is presented, typed as one, while its expiry lies after the instant.</summary>
    [TestMethod]
    public void TheIdTokenIsPresentedWhileItHolds()
    {
        var selected = IdJagSubjectTokenSelection.Select(
            new IdJagHeldSubject("id-token", Now.AddSeconds(1), "refresh-token"), IdJagSubjectTokenPreference.IdToken, Now);

        Assert.AreEqual(new IdJagSubjectToken("id-token", TokenType.IdToken), selected);
    }


    /// <summary>An ID Token whose expiry is the instant itself is run out, and nothing is presented under the ID Token preference.</summary>
    [TestMethod]
    public void AnIdTokenRunOutIsNeverPresented()
    {
        var selected = IdJagSubjectTokenSelection.Select(
            new IdJagHeldSubject("id-token", Now, "refresh-token"), IdJagSubjectTokenPreference.IdToken, Now);

        Assert.IsNull(selected);
    }


    /// <summary>The refresh token is presented, typed as one, where the preference names it and one is held.</summary>
    [TestMethod]
    public void TheRefreshTokenIsPresentedWhereThePreferenceNamesIt()
    {
        var selected = IdJagSubjectTokenSelection.Select(
            new IdJagHeldSubject("id-token", Now, "refresh-token"), IdJagSubjectTokenPreference.RefreshToken, Now);

        Assert.AreEqual(new IdJagSubjectToken("refresh-token", TokenType.RefreshToken), selected);
    }


    /// <summary>The refresh token preference presents nothing where no refresh token is held.</summary>
    [TestMethod]
    public void NoRefreshTokenHeldPresentsNothing()
    {
        var selected = IdJagSubjectTokenSelection.Select(
            new IdJagHeldSubject("id-token", Now.AddSeconds(60), RefreshToken: null), IdJagSubjectTokenPreference.RefreshToken, Now);

        Assert.IsNull(selected);
    }
}
