using Verifiable.Core.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;


/// <summary>
/// Integration tests for the disclosure lattice with realistic scenarios.
/// </summary>
[TestClass]
internal sealed class DisclosureLatticeIntegrationTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void EcdsaSd2023ScenarioWithMandatoryAndSelectiveClaims()
    {
        //Simulate ECDSA-SD-2023 scenario with statement indexes.
        //Full credential has 24 statements.
        //Mandatory indexes: 0, 12, 13, 17 (issuer-related statements).
        //Non-mandatory indexes: 1-11, 14-16, 18-23.
        var allIndexes = new HashSet<int>(Enumerable.Range(0, 24));
        var mandatoryIndexes = new HashSet<int> { 0, 12, 13, 17 };

        var lattice = new SetDisclosureLattice<int>(allIndexes, mandatoryIndexes);

        //Verifier requests specific claims (statement indexes).
        //Some of these might be mandatory, some selective.
        var verifierRequest = new HashSet<int> { 0, 5, 7, 12, 18, 19 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(lattice, verifierRequest);

        Assert.IsTrue(result.SatisfiesRequirements, "All requested claims are available.");

        //Result must include all mandatory plus requested selective.
        Assert.IsTrue(result.SelectedClaims.IsSupersetOf(mandatoryIndexes), "All mandatory must be included.");
        Assert.Contains(5, result.SelectedClaims, "Requested selective claim 5 must be included.");
        Assert.Contains(7, result.SelectedClaims, "Requested selective claim 7 must be included.");
        Assert.Contains(18, result.SelectedClaims, "Requested selective claim 18 must be included.");
        Assert.Contains(19, result.SelectedClaims, "Requested selective claim 19 must be included.");
    }


    [TestMethod]
    public void SdJwtScenarioWithClaimNames()
    {
        //Simulate SD-JWT scenario with claim names.
        var allClaims = new HashSet<string>
    {
        "iss", "sub", "iat", "exp",
        "given_name", "family_name", "email", "phone_number",
        "address", "birthdate"
    };

        //iss, sub, iat, exp are typically mandatory.
        var mandatoryClaims = new HashSet<string> { "iss", "sub", "iat", "exp" };

        var lattice = new SetDisclosureLattice<string>(allClaims, mandatoryClaims);

        //Verifier requests name and email.
        var verifierRequest = new HashSet<string> { "given_name", "family_name", "email" };

        //User excludes phone number.
        var userExclusions = new HashSet<string> { "phone_number", "address" };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(
            lattice,
            verifierRequest,
            userExclusions);

        Assert.IsTrue(result.SatisfiesRequirements, "All requested claims are available and not excluded.");
        Assert.Contains("iss", result.SelectedClaims, "Mandatory claim iss must be included.");
        Assert.Contains("given_name", result.SelectedClaims, "Requested claim given_name must be included.");
        Assert.DoesNotContain("phone_number", result.SelectedClaims, "Excluded claim phone_number must not be included.");
    }


    [TestMethod]
    public void UserExcludesRequestedClaimCausesConflict()
    {
        var allClaims = new HashSet<string> { "name", "email", "phone", "address" };
        var mandatoryClaims = new HashSet<string> { "name" };

        var lattice = new SetDisclosureLattice<string>(allClaims, mandatoryClaims);

        //Verifier requires email.
        var verifierRequest = new HashSet<string> { "email" };

        //User excludes email.
        var userExclusions = new HashSet<string> { "email" };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(
            lattice,
            verifierRequest,
            userExclusions);

        Assert.IsFalse(result.SatisfiesRequirements, "Conflict when user excludes required claim.");
        Assert.IsNotNull(result.ConflictingClaims, "Conflict must be reported.");
        Assert.Contains("email", result.ConflictingClaims, "Email must be in conflicts.");
    }


    [TestMethod]
    public void UserCannotExcludeMandatoryClaims()
    {
        var allClaims = new HashSet<string> { "iss", "sub", "name", "email" };
        var mandatoryClaims = new HashSet<string> { "iss", "sub" };

        var lattice = new SetDisclosureLattice<string>(allClaims, mandatoryClaims);

        //User tries to exclude mandatory claim.
        var userExclusions = new HashSet<string> { "iss", "email" };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(
            lattice,
            verifierRequested: null,
            userExclusions: userExclusions);

        Assert.IsTrue(result.SatisfiesRequirements, "No verifier requirements means satisfied.");
        Assert.Contains("iss", result.SelectedClaims, "Mandatory claim iss cannot be excluded.");
        Assert.Contains("sub", result.SelectedClaims, "Mandatory claim sub must be included.");
        Assert.DoesNotContain("email", result.SelectedClaims, "Non-mandatory email can be excluded.");
    }
}
