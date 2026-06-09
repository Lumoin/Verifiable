using System;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Spec tests for the RFC 9470 §3 step-up authentication challenge builder
/// (<see cref="StepUpAuthenticationChallenge"/>). The two happy-path cases reproduce the
/// section's verbatim examples (as the logical single-line header value); the rest pin the
/// auth-param ordering, the space-separated <c>acr_values</c> list, quoted-string escaping,
/// and the argument guards.
/// </summary>
[TestClass]
internal sealed class StepUpAuthenticationChallengeTests
{
    /// <summary>RFC 9470 §3, first example: an <c>acr_values</c> requirement.</summary>
    [TestMethod]
    public void AcrValuesChallengeMatchesRfc9470Example1()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            acrValues: ["myACR"],
            errorDescription: "A different authentication level is required");

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", " +
            "error_description=\"A different authentication level is required\", " +
            "acr_values=\"myACR\"",
            challenge);
    }


    /// <summary>RFC 9470 §3, second example: a <c>max_age</c> requirement.</summary>
    [TestMethod]
    public void MaxAgeChallengeMatchesRfc9470Example2()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            maxAgeSeconds: 5,
            errorDescription: "More recent authentication is required");

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", " +
            "error_description=\"More recent authentication is required\", " +
            "max_age=\"5\"",
            challenge);
    }


    /// <summary>§3: the <c>acr_values</c> are a space-separated list in order of preference.</summary>
    [TestMethod]
    public void AcrValuesAreSpaceJoinedInPreferenceOrder()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            acrValues: ["urn:loa:high", "urn:loa:medium"]);

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", " +
            "acr_values=\"urn:loa:high urn:loa:medium\"",
            challenge);
    }


    /// <summary>Both requirements present: error, then <c>acr_values</c>, then <c>max_age</c>.</summary>
    [TestMethod]
    public void AcrValuesAndMaxAgeAppearInSpecParameterOrder()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            acrValues: ["myACR"],
            maxAgeSeconds: 5);

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", " +
            "acr_values=\"myACR\", max_age=\"5\"",
            challenge);
    }


    /// <summary>§3 / RFC 6750 §3.1: the optional <c>scope</c> attribute is space-joined.</summary>
    [TestMethod]
    public void ScopeAttributeIsEmittedSpaceJoined()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            scopes: ["purchase", "admin"]);

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", scope=\"purchase admin\"",
            challenge);
    }


    /// <summary>All requirements together: error, acr_values, max_age, then scope.</summary>
    [TestMethod]
    public void AcrValuesMaxAgeAndScopeAppearInOrder()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            acrValues: ["myACR"],
            maxAgeSeconds: 5,
            scopes: ["purchase"]);

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", " +
            "acr_values=\"myACR\", max_age=\"5\", scope=\"purchase\"",
            challenge);
    }


    /// <summary>With no requirements supplied, only the error parameter is emitted.</summary>
    [TestMethod]
    public void ErrorOnlyChallengeOmitsAbsentParameters()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer);

        Assert.AreEqual("Bearer error=\"insufficient_user_authentication\"", challenge);
    }


    /// <summary>§3: the challenge rides the DPoP scheme as readily as Bearer.</summary>
    [TestMethod]
    public void DpopSchemeIsHonoured()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.DPoP,
            acrValues: ["myACR"]);

        Assert.AreEqual(
            "DPoP error=\"insufficient_user_authentication\", acr_values=\"myACR\"",
            challenge);
    }


    /// <summary>RFC 9110 §5.6.4: <c>"</c> and <c>\</c> inside a quoted-string are backslash-escaped.</summary>
    [TestMethod]
    public void ErrorDescriptionQuotedStringSpecialCharactersAreEscaped()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            errorDescription: "say \"hi\" \\ bye");

        Assert.AreEqual(
            "Bearer error=\"insufficient_user_authentication\", " +
            "error_description=\"say \\\"hi\\\" \\\\ bye\"",
            challenge);
    }


    /// <summary>The error value is the shared <see cref="OAuthErrors.InsufficientUserAuthentication"/> constant.</summary>
    [TestMethod]
    public void ErrorValueIsTheSharedOAuthErrorConstant()
    {
        string challenge = StepUpAuthenticationChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer);

        Assert.Contains(
            $"error=\"{OAuthErrors.InsufficientUserAuthentication}\"", challenge, StringComparison.Ordinal);
    }


    /// <summary>A negative <c>max_age</c> is rejected.</summary>
    [TestMethod]
    public void NegativeMaxAgeThrows()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => StepUpAuthenticationChallenge.BuildChallenge(
                WellKnownAuthenticationSchemes.Bearer, maxAgeSeconds: -1));
    }


    /// <summary>A missing scheme is rejected.</summary>
    [TestMethod]
    public void EmptySchemeThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => StepUpAuthenticationChallenge.BuildChallenge(" "));
    }
}
