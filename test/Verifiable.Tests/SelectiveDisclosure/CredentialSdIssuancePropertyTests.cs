using CsCheck;
using Verifiable.Cbor.Sd;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Json.Sd;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Property-based tests for W3C Verifiable Credential path validation in
/// <see cref="SdJwtExtensions.ValidateCredentialPaths"/> and
/// <see cref="SdCwtExtensions.ValidateCredentialPaths"/>.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the path validation boundary with random paths that are
/// prefixes, suffixes, or near-misses of <c>/credentialSubject</c>. CsCheck generates
/// paths that stress the boundary condition between valid and invalid disclosure paths.
/// </para>
/// <para>
/// Example-based tests for the same API are in
/// <see cref="CredentialSdIssuanceTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CredentialSdIssuancePropertyTests
{
    [TestMethod]
    public void AnyPathUnderCredentialSubjectIsAccepted()
    {
        Gen.String[Gen.Char.AlphaNumeric, 1, 20].Sample(segment =>
        {
            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/credentialSubject/{segment}")
            };

            SdJwtExtensions.ValidateCredentialPaths(paths);
        });
    }


    [TestMethod]
    public void AnyTopLevelPathOutsideCredentialSubjectIsRejected()
    {
        Gen.String[Gen.Char.AlphaNumeric, 1, 20]
        .Where(name => !name.StartsWith("credentialSubject", StringComparison.Ordinal))
        .Sample(name =>
        {
            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{name}")
            };

            Assert.Throws<ArgumentException>(() =>
                SdJwtExtensions.ValidateCredentialPaths(paths));
        });
    }


    [TestMethod]
    public void DeeplyNestedCredentialSubjectPathsAreAccepted()
    {
        (from segments in Gen.String[Gen.Char.AlphaNumeric, 1, 10].Array[1, 5]
         select segments)
        .Sample(segments =>
        {
            string path = "/credentialSubject/" + string.Join("/", segments);
            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer(path)
            };

            SdJwtExtensions.ValidateCredentialPaths(paths);
        });
    }


    [TestMethod]
    public void MixedValidAndInvalidPathsRejectsEntireSet()
    {
        Gen.String[Gen.Char.AlphaNumeric, 1, 15]
        .Where(name => !name.StartsWith("credentialSubject", StringComparison.Ordinal))
        .Sample(invalidName =>
        {
            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer("/credentialSubject/id"),
                CredentialPath.FromJsonPointer("/credentialSubject/degree"),
                CredentialPath.FromJsonPointer($"/{invalidName}")
            };

            Assert.Throws<ArgumentException>(() =>
                SdJwtExtensions.ValidateCredentialPaths(paths));
        });
    }


    [TestMethod]
    public void CwtPathValidationMatchesJwtPathValidation()
    {
        //Both JWT and CWT extensions must enforce the same path boundary.
        Gen.String[Gen.Char.AlphaNumeric, 1, 20]
        .Where(name => !name.StartsWith("credentialSubject", StringComparison.Ordinal))
        .Sample(name =>
        {
            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{name}")
            };

            Assert.Throws<ArgumentException>(() =>
                SdJwtExtensions.ValidateCredentialPaths(paths));

            Assert.Throws<ArgumentException>(() =>
                SdCwtExtensions.ValidateCredentialPaths(paths));
        });
    }
}