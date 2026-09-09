using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests that a parsed selective-disclosure token knows where each of its disclosures sits, and
/// that a selection expressed as positions releases exactly the disclosures those positions
/// name plus the ancestors that make them readable.
/// </summary>
/// <remarks>
/// <para>
/// The credential under test is <see cref="NestedSdJwtVcFixtures"/>'s: a claim name that occurs
/// at two depths, array elements behind a decoy, and a recursively disclosable object. The
/// governing text is <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> for what
/// a disclosure's position is and which disclosures a presentation may carry, and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
/// Verifiable Presentations 1.0</see> for the obligation not to release what was not selected.
/// </para>
/// </remarks>
[SuppressMessage(
    "Reliability", "CA2000",
    Justification =
        "The hand-minted malformed tokens construct Salt instances and hand them to SdDisclosure " +
        "factory methods that take ownership; those disclosures are disposed in the helper's own " +
        "finally block once their wire text has been read, and every token this class holds is " +
        "disposed through a using declaration. The analyzer cannot see ownership transfer " +
        "through factory methods.")]
[TestClass]
internal sealed class SdTokenPathSelectionTests
{
    /// <summary>The per-test context, source of the cancellation token every asynchronous call takes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The pool this class passes explicitly to every mint, parse and selection call.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The claim key the SD-CWT twin carries <c>family_name</c> under, at both depths.</summary>
    private const int FamilyNameClaimKey = 500;

    /// <summary>The claim key the SD-CWT twin carries the employer map under.</summary>
    private const int EmployerClaimKey = 501;

    /// <summary>The <c>kid</c> the SD-CWT twin's issuer signs under.</summary>
    private const string SdCwtIssuerKeyId = "did:web:issuer.example.com#cwt-key-1";

    /// <summary>
    /// A COSE protected header the parse under test reads as opaque bytes: an empty CBOR map. The
    /// parse resolves digests and never checks the signature, so the hand-minted SD-CWT needs no
    /// issuer key.
    /// </summary>
    private static ReadOnlyMemory<byte> UnverifiableCoseProtectedHeader { get; } = new byte[] { 0xA0 };

    /// <summary>A placeholder COSE signature, for the same reason as <see cref="UnverifiableCoseProtectedHeader"/>.</summary>
    private static ReadOnlyMemory<byte> UnverifiableCoseSignature { get; } = new byte[64];


    /// <summary>
    /// Proves that a claim name recurring at two depths yields two disclosures at two positions.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>: "The
    /// Issuer MUST ensure that a new salt value is chosen for each claim, including when the same
    /// claim name occurs at different places in the structure of the SD-JWT." Section 4.2.1 fixes
    /// what the name means: "The claim name, or key, as it would be used in a regular JWT
    /// payload." — a name local to its containing object, so the position is that object's path
    /// plus the name.
    /// </summary>
    [TestMethod]
    public async Task DisclosurePathsGiveEachNamesakeItsOwnPosition()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(
            NestedSdJwtVcFixtures.TopLevelFamilyNamePath,
            credential.Token.DisclosurePaths.Paths,
            "Section 9.3: the top-level occurrence of the name is a disclosure of its own, at the root object's path plus the name.");
        Assert.Contains(
            NestedSdJwtVcFixtures.EmployerFamilyNamePath,
            credential.Token.DisclosurePaths.Paths,
            "Section 9.3: the occurrence one level down is a separate disclosure, at its own containing object's path plus the name.");

        bool isTopLevelResolved = credential.Token.DisclosurePaths.TryGetDisclosure(
            NestedSdJwtVcFixtures.TopLevelFamilyNamePath, out SdDisclosure? topLevel);
        bool isNestedResolved = credential.Token.DisclosurePaths.TryGetDisclosure(
            NestedSdJwtVcFixtures.EmployerFamilyNamePath, out SdDisclosure? nested);

        Assert.IsTrue(isTopLevelResolved, "The top-level position must resolve to a disclosure.");
        Assert.IsTrue(isNestedResolved, "The nested position must resolve to a disclosure.");
        Assert.AreEqual(
            NestedSdJwtVcFixtures.TopLevelFamilyName,
            topLevel!.ClaimValue,
            "Section 9.3: the two namesakes are distinct disclosures, so each position must resolve to its own value.");
        Assert.AreEqual(
            NestedSdJwtVcFixtures.EmployerFamilyName,
            nested!.ClaimValue,
            "Section 9.3: the two namesakes are distinct disclosures, so each position must resolve to its own value.");
        Assert.AreNotEqual(
            topLevel,
            nested,
            "Section 9.3: a new salt is chosen for each occurrence, so the two namesakes are never the same disclosure.");
    }


    /// <summary>
    /// Proves the parse assigns every disclosure the position the specification's rules give it,
    /// and no other. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section
    /// 4.2.1</see> gives an object property "The claim name, or key, as it would be used in a
    /// regular JWT payload", Section 4.2.2 gives an array element its index, and Section 6 states
    /// that "the _sd key containing digests MAY appear multiple times in an SD-JWT, and likewise,
    /// there MAY be multiple arrays within the hierarchy with each having selectively disclosable
    /// elements."
    /// </summary>
    [TestMethod]
    public async Task DisclosurePathsAreExactlyThePositionsTheSpecificationAssigns()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            credential.Token.DisclosurePaths.Paths.SetEquals(NestedSdJwtVcFixtures.ExpectedDisclosurePaths),
            $"Sections 4.2.1, 4.2.2 and 6 fix every position; the parse resolved [{Render(credential.Token.DisclosurePaths.Paths)}].");
        Assert.AreEqual(
            NestedSdJwtVcFixtures.ExpectedDisclosurePaths.Count,
            credential.Token.DisclosurePaths.Count,
            "Every disclosure the wire form carries occupies exactly one position.");
    }


    /// <summary>
    /// Proves an array element's position is the index its marker has in the issuer-signed
    /// structure, counting markers that resolve to nothing.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.2</see>: "The
    /// array MUST contain two elements in this order: 1. The salt value as described in Section
    /// 4.2.1. 2. The array element that is to be hidden." — an array-element disclosure carries no
    /// name, so only its position identifies it; Section 4.2.5's decoys occupy positions in that
    /// same structure.
    /// </summary>
    [TestMethod]
    public async Task ArrayElementDisclosureKeepsTheIndexItsMarkerHasAsIssued()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        AssertElementAt(credential, NestedSdJwtVcFixtures.FirstNationalityPath, NestedSdJwtVcFixtures.FirstNationality);
        AssertElementAt(credential, NestedSdJwtVcFixtures.SecondNationalityPath, NestedSdJwtVcFixtures.SecondNationality);
        AssertElementAt(credential, NestedSdJwtVcFixtures.ThirdNationalityPath, NestedSdJwtVcFixtures.ThirdNationality);

        Assert.DoesNotContain(
            CredentialPath.FromJsonPointer("/nationalities/0"),
            credential.Token.DisclosurePaths.Paths,
            "Index 0 is the decoy marker's; Section 4.2.5's decoy is backed by no disclosure, so no disclosure sits there.");
    }


    /// <summary>
    /// Proves a member of a recursively disclosable object resolves through its parent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.6</see>: "The
    /// algorithms above are compatible with 'recursive Disclosures', in which one selectively
    /// disclosed field reveals the existence of more selectively disclosable fields." Section 6
    /// states the same of nesting: "Digests of selectively disclosable claims MAY even appear
    /// within other Disclosures."
    /// </summary>
    [TestMethod]
    public async Task RecursiveMemberResolvesThroughItsParentsPath()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(
            NestedSdJwtVcFixtures.AddressPath,
            credential.Token.DisclosurePaths.Paths,
            "Section 4.2.6: the whole address field is itself selectively disclosable.");
        Assert.Contains(
            NestedSdJwtVcFixtures.StreetAddressPath,
            credential.Token.DisclosurePaths.Paths,
            "Section 4.2.6: a digest inside another Disclosure's value resolves at the parent's path plus its name.");
        Assert.Contains(
            NestedSdJwtVcFixtures.LocalityPath,
            credential.Token.DisclosurePaths.Paths,
            "Section 4.2.6: a digest inside another Disclosure's value resolves at the parent's path plus its name.");
        Assert.Contains(
            NestedSdJwtVcFixtures.CountryPath,
            credential.Token.DisclosurePaths.Paths,
            "Section 4.2.6: a digest inside another Disclosure's value resolves at the parent's path plus its name.");

        Assert.Contains(
            NestedSdJwtVcFixtures.NationalitiesPath,
            credential.Token.DisclosurePaths.Paths,
            "Section 4.2.6: 'Followed by making the whole \"nationalities\" array selectively disclosable'.");
        Assert.IsTrue(
            NestedSdJwtVcFixtures.NationalitiesPath.IsAncestorOf(NestedSdJwtVcFixtures.SecondNationalityPath),
            "Section 4.2.6: an element of a recursively disclosed array is addressed through the array it belongs to.");
    }


    /// <summary>
    /// Proves the always-disclosed claims are carried as themselves and the mechanism keys are
    /// not. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 7.1</see> steps
    /// 3.e and 3.f: "Remove all _sd keys and their contents from the Issuer-signed JWT payload"
    /// and "Remove the claim _sd_alg from the SD-JWT payload." The three claims that remain are
    /// the SD-JWT VC evidence claims of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>, which designates them and states that they "MUST NOT be
    /// included in the Disclosures, i.e., cannot be selectively disclosed": "vct: REQUIRED. The
    /// type of the Verifiable Digital Credential", "aka_vcts: OPTIONAL. An array of additional
    /// types of the Verifiable Digital Credential" and "iss: OPTIONAL".
    /// </summary>
    [TestMethod]
    public async Task IssuerSignedClaimsCarryTheAlwaysDisclosedClaimsAndNoMechanismKeys()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<CredentialPath, object?> claims = credential.Token.IssuerSignedClaims;

        Assert.IsTrue(
            claims.TryGetValue(NestedSdJwtVcFixtures.VctPath, out object? vct),
            "SD-JWT VC Section 2.2.2.3 makes vct REQUIRED and not selectively disclosable, so it is unconditionally disclosed.");
        Assert.AreEqual(NestedSdJwtVcFixtures.Vct, vct, "The type claim carries the credential's own type.");

        Assert.IsTrue(
            claims.TryGetValue(NestedSdJwtVcFixtures.IssuerPath, out object? issuer),
            "SD-JWT VC Section 2.2.2.3's iss is not selectively disclosable, so it is unconditionally disclosed.");
        Assert.AreEqual(NestedSdJwtVcFixtures.Issuer, issuer, "The issuer claim carries the credential's own issuer.");

        Assert.IsTrue(
            claims.ContainsKey(NestedSdJwtVcFixtures.AkaVctsPath),
            "SD-JWT VC Section 2.2.2.3's aka_vcts is not selectively disclosable, so it is unconditionally disclosed.");

        foreach(CredentialPath path in claims.Keys)
        {
            string pointer = path.ToString();
            Assert.IsFalse(
                pointer.EndsWith($"/{SdConstants.SdClaimName}", StringComparison.Ordinal),
                $"Section 7.1 step 3.e removes every _sd key; '{pointer}' is one.");
            Assert.IsFalse(
                pointer.EndsWith($"/{SdConstants.SdAlgorithmClaimName}", StringComparison.Ordinal),
                $"Section 7.1 step 3.f removes the _sd_alg claim; '{pointer}' is it.");
            Assert.IsFalse(
                pointer.EndsWith($"/{SdConstants.ArrayDigestKey}", StringComparison.Ordinal),
                $"Section 4.2.2's array markers are structure, not claims; '{pointer}' is one.");
        }
    }


    /// <summary>
    /// Proves selecting the top-level namesake releases that disclosure and nothing else.
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below."
    /// </summary>
    [TestMethod]
    public async Task SelectingTheTopLevelNamesakeReleasesThatDisclosureAlone()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.TopLevelFamilyNamePath }, Pool);

        using SdToken<string> presented = selection.Token;

        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.TopLevelFamilyNamePath],
            "Section 6.4: only the selected claim may be sent.");
        Assert.IsEmpty(selection.UnmatchedPaths, "A path the credential carries is never unmatched.");
    }


    /// <summary>
    /// Proves selecting the nested namesake releases it together with the disclosable parent that
    /// makes it readable, and never the top-level namesake.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 7.2</see> step 2:
    /// "Verify that each selected Disclosure satisfies one of the two following conditions: a.
    /// The hash of the Disclosure is contained in the Issuer-signed JWT claims. b. The hash of the
    /// Disclosure is contained in the claim value of another selected Disclosure."
    /// </summary>
    [TestMethod]
    public async Task SelectingTheNestedNamesakeReleasesItWithItsDisclosableAncestor()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.EmployerFamilyNamePath }, Pool);

        using SdToken<string> presented = selection.Token;

        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.EmployerPath, NestedSdJwtVcFixtures.EmployerFamilyNamePath],
            "Section 7.2 step 2.b: the nested Disclosure's hash sits in the parent Disclosure's value, so the parent rides along.");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.TopLevelFamilyNamePath,
            presented.DisclosurePaths.Paths,
            "The namesake at the root was not selected and must not be released.");
    }


    /// <summary>
    /// Proves selecting one array element releases that element and the array that carries it,
    /// and no sibling element. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901,
    /// Section 4.2.6</see>: "the Holder could include the Disclosure with hash PmnlrRj... to
    /// disclose only the 'DE' nationality ... In either case, the Holder would also need to
    /// include the Disclosure with hash 5G1srw3... to disclose the nationalities field that
    /// contains the respective elements."
    /// </summary>
    [TestMethod]
    public async Task SelectingOneArrayElementReleasesThatElementAndItsArray()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.FirstNationalityPath }, Pool);

        using SdToken<string> presented = selection.Token;

        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.NationalitiesPath, NestedSdJwtVcFixtures.FirstNationalityPath],
            "Section 4.2.6: the selected element plus the field that contains it, and nothing more.");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.SecondNationalityPath,
            presented.DisclosurePaths.Paths,
            "Section 4.2.6: the other nationalities stay hidden.");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.ThirdNationalityPath,
            presented.DisclosurePaths.Paths,
            "Section 4.2.6: the other nationalities stay hidden.");
    }


    /// <summary>
    /// Proves selecting a member of the recursively disclosable address releases the whole chain
    /// down to it and no sibling member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 7.2</see> step 2.b:
    /// "The hash of the Disclosure is contained in the claim value of another selected
    /// Disclosure."
    /// </summary>
    [TestMethod]
    public async Task SelectingARecursiveAddressMemberReleasesItsChain()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.LocalityPath }, Pool);

        using SdToken<string> presented = selection.Token;

        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.AddressPath, NestedSdJwtVcFixtures.LocalityPath],
            "Section 7.2 step 2.b: the address Disclosure carries the locality digest, so it is released with it.");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.StreetAddressPath,
            presented.DisclosurePaths.Paths,
            "Section 6's other address members were not selected and stay hidden.");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.CountryPath,
            presented.DisclosurePaths.Paths,
            "Section 6's other address members were not selected and stay hidden.");
    }


    /// <summary>
    /// Proves a position named twice in one selection releases its disclosure once.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4</see>: "A Holder
    /// MUST NOT send a Disclosure that was not included in the issued SD-JWT or send a Disclosure
    /// more than once."
    /// </summary>
    [TestMethod]
    public async Task SelectingAPositionTwiceReleasesItsDisclosureOnce()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        //A set built from the same pointer text twice: the caller's request names the position
        //again, which must not put the same Disclosure on the wire twice.
        var repeated = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/family_name"),
            CredentialPath.FromJsonPointer("/family_name")
        };

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(repeated, Pool);

        using SdToken<string> presented = selection.Token;

        Assert.HasCount(
            1,
            presented.Disclosures,
            "Section 4: a Holder must not send a Disclosure more than once, so a selection emits each Disclosure once.");
        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.TopLevelFamilyNamePath],
            "Section 4: the repeated position still names one Disclosure.");
    }


    /// <summary>
    /// Proves selecting a parent and its child releases each disclosure once.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4</see>: "A Holder
    /// MUST NOT send a Disclosure that was not included in the issued SD-JWT or send a Disclosure
    /// more than once." — the parent the closure of Section 7.2 step 2.b would add anyway must not
    /// be added a second time.
    /// </summary>
    [TestMethod]
    public async Task SelectingAParentAndItsChildReleasesEachDisclosureOnce()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath>
            {
                NestedSdJwtVcFixtures.EmployerPath,
                NestedSdJwtVcFixtures.EmployerFamilyNamePath
            },
            Pool);

        using SdToken<string> presented = selection.Token;

        Assert.HasCount(
            2,
            presented.Disclosures,
            "Section 4: the parent named explicitly and the parent the closure adds are one Disclosure.");
        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.EmployerPath, NestedSdJwtVcFixtures.EmployerFamilyNamePath],
            "Section 7.2 step 2 admits exactly these two.");
    }


    /// <summary>
    /// Proves a position that names an always-disclosed claim releases no disclosure and is not
    /// reported as unmatched. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section
    /// 7.2</see> step 1: "Decide which Disclosures to release to the Verifier" — a claim that was
    /// never made selectively disclosable has no Disclosure to release, and
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see> constrains only "selectively disclosable
    /// claims".
    /// </summary>
    [TestMethod]
    public async Task AnAlwaysDisclosedPositionReleasesNothingAndIsNotReportedUnmatched()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.VctPath }, Pool);

        using SdToken<string> presented = selection.Token;

        Assert.IsEmpty(
            presented.Disclosures,
            "Section 7.2 step 1: an always-disclosed claim has no Disclosure to release.");
        Assert.IsEmpty(
            selection.UnmatchedPaths,
            "The credential does carry the claim, so the position matched something even though it released nothing.");
    }


    /// <summary>
    /// Proves a position the credential does not carry is reported back and does not stop the
    /// selection. <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">
    /// OpenID for Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send
    /// selectively disclosable claims that have not been selected according to the rules below."
    /// — an unresolvable position selects nothing, so nothing extra can be sent for it.
    /// </summary>
    [TestMethod]
    public async Task APositionTheCredentialDoesNotCarryIsReportedUnmatchedAndTheSelectionStillReturns()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        CredentialPath absent = CredentialPath.FromJsonPointer("/employer/given_name");

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.TopLevelFamilyNamePath, absent }, Pool);

        using SdToken<string> presented = selection.Token;

        Assert.Contains(
            absent,
            selection.UnmatchedPaths,
            "A position addressing nothing in the credential is reported so the caller can decide.");
        Assert.HasCount(1, selection.UnmatchedPaths, "Only the absent position is unmatched.");
        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.TopLevelFamilyNamePath],
            "Section 6.4: what did resolve is still released, and nothing else.");
    }


    /// <summary>
    /// Proves a payload whose <c>_sd</c> array resolves two disclosures to the same name at one
    /// level is refused. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section
    /// 7.1</see> step 3.c.ii.3: "If the claim name already exists at the level of the _sd key, the
    /// SD-JWT MUST be rejected."
    /// </summary>
    [TestMethod]
    public void TwoDisclosuresWithOneNameAtOneLevelAreRefusedAtParse()
    {
        string compactSdJwt = MintSameLevelDuplicateName();

        FormatException failure = Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 7.1 step 3.c.ii.3: the SD-JWT MUST be rejected, never parsed with one namesake silently overwriting the other.");

        Assert.Contains(
            NestedSdJwtVcFixtures.FamilyNameClaim,
            failure.Message,
            "The refusal names the colliding claim so the holder can see which level is malformed.");
    }


    /// <summary>
    /// Proves a wire form carrying a disclosure no digest refers to is refused.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 7.1</see> step 5: "If
    /// any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or
    /// recursively via other Disclosures), the SD-JWT MUST be rejected."
    /// </summary>
    [TestMethod]
    public void ADisclosureNoDigestReferencesIsRefusedAtParse()
    {
        string compactSdJwt = MintUnreferencedDisclosure();

        Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 7.1 step 5: an unreferenced Disclosure makes the SD-JWT invalid, never a silently dropped extra.");
    }


    /// <summary>
    /// Proves a Disclosure whose claim name is one of the mechanism keys is refused.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.1</see>: "The claim
    /// name, or key, as it would be used in a regular JWT payload. It MUST be a string and MUST NOT
    /// be _sd or ...", which Section 7.1 step 3.c.ii.2 enforces at the Verifier.
    /// </summary>
    /// <param name="mechanismKey">The mechanism key the malformed Disclosure claims as its name.</param>
    [TestMethod]
    [DataRow(SdConstants.SdClaimName)]
    [DataRow(SdConstants.ArrayDigestKey)]
    public void ADisclosureNamedAfterAMechanismKeyIsRefusedAtParse(string mechanismKey)
    {
        string compactSdJwt = MintDisclosureNamed(mechanismKey, "anything");

        FormatException failure = Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 4.2.1: a claim name MUST NOT be _sd or ..., so a Disclosure claiming one is malformed.");

        Assert.Contains(
            mechanismKey,
            failure.Message,
            StringComparison.Ordinal,
            "The refusal names the mechanism key the Disclosure tried to claim.");
    }


    /// <summary>
    /// Proves a Disclosure whose claim name is already present in its containing object as a
    /// permanently disclosed claim is refused.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.1</see>: the claim
    /// name "MUST NOT be _sd or ..., or a claim name existing in the object as a permanently
    /// disclosed claim", which Section 7.1 step 3.c.ii.3 enforces: "If the claim name already
    /// exists at the level of the _sd key, the SD-JWT MUST be rejected."
    /// </summary>
    [TestMethod]
    public void ADisclosureCollidingWithAPermanentlyDisclosedSiblingIsRefusedAtParse()
    {
        string compactSdJwt = MintDisclosureCollidingWithPlainSibling();

        FormatException failure = Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 4.2.1: a Disclosure must not claim a name the object already carries in the clear.");

        Assert.Contains(
            NestedSdJwtVcFixtures.FamilyNameClaim,
            failure.Message,
            StringComparison.Ordinal,
            "The refusal names the claim the Disclosure collided with.");
    }


    /// <summary>
    /// Proves an <c>_sd</c> value that is not an array of strings identifies no digest at all.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 7.1</see> step 3.b.i
    /// reads the key's value as "an array of strings"; an array carrying anything else is not that,
    /// so no member of it resolves a Disclosure — the string members are not picked out of an
    /// inadmissible value.
    /// </summary>
    [TestMethod]
    public void AnSdArrayCarryingANonStringMemberResolvesNoDisclosure()
    {
        string compactSdJwt = MintSdArrayWithNonStringMember();

        Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 7.1 step 3.b.i: the array identifies no digest, so the Disclosure the wire form carries is unreferenced and step 5 refuses the token.");
    }


    /// <summary>
    /// Proves the SD-CWT twin of the mechanism-key rule: a redacted-claim-key digest that resolves
    /// to a Disclosure named after one of the redaction mechanism's own labels is refused. The CBOR
    /// profile mirrors <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section
    /// 4.2.1</see>'s "It MUST be a string and MUST NOT be _sd or ...".
    /// </summary>
    [TestMethod]
    public void SdCwtADisclosureNamedAfterAMechanismLabelIsRefusedAtParse()
    {
        byte[] wireBytes = MintSdCwtDisclosureNamedAfterAMechanismLabel();

        FormatException failure = Assert.Throws<FormatException>(
            () => SdCwtSerializer.ParseToken(wireBytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder),
            "Section 4.2.1's rule for the CBOR profile: a Disclosure must not claim one of the redaction mechanism's own labels.");

        Assert.Contains(
            SdCwtConstants.SdClaimsHeaderKey.ToString(CultureInfo.InvariantCulture),
            failure.Message,
            StringComparison.Ordinal,
            "The refusal names the mechanism label the Disclosure tried to claim.");
    }


    /// <summary>
    /// Proves an SD-CWT Disclosure binds by the bytes the wire carried, not by what a
    /// re-serialization of the parsed value would produce.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.3</see> computes the
    /// digest over the Disclosure as it was issued, and the CBOR profile answers that rule the same
    /// way the SD-JWT side does. The Disclosure here carries its array header in a non-minimal
    /// form, which is valid CBOR holding the same three elements but is not the encoding this
    /// library would write.
    /// </summary>
    [TestMethod]
    public void SdCwtADisclosureBindsByTheBytesTheWireCarried()
    {
        byte[] wireBytes = MintSdCwtWithNonMinimalArrayHeader();

        using SdToken<ReadOnlyMemory<byte>> token = SdCwtSerializer.ParseToken(
            wireBytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder);

        Assert.Contains(
            CredentialPath.FromJsonPointer($"/{FamilyNameClaimKey}"),
            token.DisclosurePaths.Paths,
            "Section 4.2.3: the digest commits to the Disclosure's own bytes, so a validly encoded Disclosure binds however it was encoded.");
    }


    /// <summary>
    /// Proves the SD-CWT type and issuer readers pass over a text-string claim key rather than
    /// reading it as an integer. <see href="https://www.rfc-editor.org/rfc/rfc8392#section-4">RFC
    /// 8392, Section 4</see>: "The Claim Key MUST be an integer or a text string", so a private
    /// claim keyed by a text string is a well-formed CWT claim, and one sitting ahead of <c>vct</c>
    /// and <c>iss</c> in the claims map must not stop the readers from reaching them.
    /// </summary>
    [TestMethod]
    public void SdCwtTypeAndIssuerAreReadPastATextKeyedPrivateClaim()
    {
        byte[] wireBytes = MintSdCwtWithLeadingTextKeyedClaim();

        using SdToken<ReadOnlyMemory<byte>> token = SdCwtSerializer.ParseToken(
            wireBytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder);

        Assert.AreEqual(
            NestedSdJwtVcFixtures.Vct,
            SdCwtVpParsing.ExtractCredentialType(token),
            "RFC 8392 Section 4: a text-string claim key is well formed, so the vct reader passes over it and reads the type.");
        Assert.AreEqual(
            NestedSdJwtVcFixtures.Issuer,
            SdCwtVpParsing.ExtractIssuer(token),
            "RFC 8392 Section 4: a text-string claim key is well formed, so the iss reader passes over it and reads the issuer.");
    }


    /// <summary>
    /// Proves a wire form carrying two Disclosures under one salt is refused.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>: "The Issuer
    /// MUST ensure that a new salt value is chosen for each claim, including when the same claim
    /// name occurs at different places in the structure of the SD-JWT." A parse that admitted the
    /// shape would let a second Disclosure share the first's cryptographic identity, and a lookup
    /// for either would answer with whichever the parse happened to keep.
    /// </summary>
    [TestMethod]
    public void TwoDisclosuresSharingOneSaltAreRefusedAtParse()
    {
        string compactSdJwt = MintSharedSaltDisclosures();

        FormatException failure = Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 9.3: a new salt is chosen for each claim, so a wire form reusing one is malformed and never parses.");

        Assert.Contains(
            "9.3",
            failure.Message,
            StringComparison.Ordinal,
            "The refusal names the clause the wire form breaks.");
    }


    /// <summary>
    /// Proves a chain of recursive Disclosures is bounded rather than followed to the depth an
    /// attacker chose. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section
    /// 4.2.6</see>: "The algorithms above are compatible with 'recursive Disclosures', in which one
    /// selectively disclosed field reveals the existence of more selectively disclosable fields."
    /// The chain's length is the wire form's, and the parse runs before any signature is checked,
    /// so a long chain must reach the parse's own failure channel rather than the call stack.
    /// </summary>
    [TestMethod]
    public void ARecursiveDisclosureChainDeeperThanTheParseAdmitsIsRefused()
    {
        string compactSdJwt = MintRecursiveDisclosureChain(depth: 4000);

        Assert.Throws<FormatException>(
            () => SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                TestSalts.TestSaltTag),
            "Section 4.2.6: a recursive-Disclosure chain past the parse's stated depth is a refusal, never an unwindable failure.");
    }


    /// <summary>
    /// Proves a node that exists only inside a Disclosure's own value is not reported as
    /// unconditionally disclosed. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901,
    /// Section 4.2.6</see>: "The algorithms above are compatible with 'recursive Disclosures', in
    /// which one selectively disclosed field reveals the existence of more selectively disclosable
    /// fields." The <c>address</c> Disclosure's plain <c>region</c> member reaches the Verifier
    /// only when <c>address</c> is released, so treating it as unconditionally disclosed would
    /// report a claim as delivered that never goes on the wire.
    /// </summary>
    [TestMethod]
    public async Task ANodeInsideADisclosureIsCarriedApartFromTheUnconditionallyDisclosedClaims()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        CredentialPath regionPath = CredentialPath.FromJsonPointer("/address/region");

        Assert.IsFalse(
            credential.Token.IssuerSignedClaims.ContainsKey(regionPath),
            "Section 4.2.6: a member of an undisclosed Disclosure's value is not readable without releasing that Disclosure.");
        Assert.IsTrue(
            credential.Token.DisclosureInteriorClaims.TryGetValue(regionPath, out object? region),
            "The member is carried beside the unconditionally disclosed claims, as a node a Disclosure's release reveals.");
        Assert.AreEqual(
            NestedSdJwtVcFixtures.Region,
            region,
            "The interior node carries the value the Disclosure's own value holds at that position.");
    }


    /// <summary>
    /// Proves naming a node interior to a Disclosure releases the Disclosure that carries it, so
    /// the claim reaches the wire. <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901,
    /// Section 7.2</see> step 2: "Verify that each selected Disclosure satisfies one of the two
    /// following conditions: a. The hash of the Disclosure is contained in the Issuer-signed JWT
    /// claims. b. The hash of the Disclosure is contained in the claim value of another selected
    /// Disclosure." Selecting <c>/address/region</c> is a request for a claim whose only route to
    /// the Verifier is the <c>address</c> Disclosure.
    /// </summary>
    [TestMethod]
    public async Task SelectingANodeInsideADisclosureReleasesTheDisclosureThatCarriesIt()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        CredentialPath regionPath = CredentialPath.FromJsonPointer("/address/region");

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { regionPath }, Pool);

        using SdToken<string> presented = selection.Token;

        Assert.IsEmpty(
            selection.UnmatchedPaths,
            "The position addresses a node the credential carries, so it is not unmatched.");
        AssertReleased(
            presented,
            [NestedSdJwtVcFixtures.AddressPath],
            "Section 7.2 step 2: the Disclosure whose value carries the node is what the selection releases.");
        Assert.IsTrue(
            presented.DisclosureInteriorClaims.ContainsKey(regionPath),
            "The released Disclosure carries the node, so the presentation still addresses it.");
    }


    /// <summary>
    /// Proves a presentation assembled from a position-based selection verifies under the shipped
    /// verifier and reveals exactly the selected claims.
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below."
    /// </summary>
    [TestMethod]
    public async Task PresentationFromAPositionSelectionVerifiesAndRevealsOnlyTheSelectedClaims()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using NestedSdJwtVcCredential credential = await NestedSdJwtVcFixtures.MintAsync(
            privateKey, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        SdDisclosureSelectionResult<string> selection = credential.Token.SelectDisclosures(
            new HashSet<CredentialPath> { NestedSdJwtVcFixtures.EmployerFamilyNamePath }, Pool);

        string presentation;
        using(SdToken<string> selected = selection.Token)
        {
            presentation = SdJwtSerializer.SerializeToken(selected, TestSetup.Base64UrlEncoder);
        }

        using SdToken<string> received = SdJwtSerializer.ParseToken(
            presentation, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);

        SdVerificationResult result = await received.VerifyAsync(
            publicKey, Pool, SdJwtPathExtraction.ExtractPaths,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The presentation the holder assembled from the selection must verify as issued.");
        Assert.AreEqual(
            SdVerificationFailureReason.None,
            result.FailureReason,
            "Section 7.1: every released Disclosure binds to a digest the payload carries, so the verification names no failure.");

        var revealed = new HashSet<CredentialPath>();
        foreach(SdClaimVerificationResult claimResult in result.ClaimResults)
        {
            Assert.IsTrue(claimResult.IsValid, "Every claim the presentation carries must bind to a position in the signed payload.");
            revealed.Add(claimResult.Path);
        }

        Assert.IsTrue(
            revealed.SetEquals(new HashSet<CredentialPath>
            {
                NestedSdJwtVcFixtures.EmployerPath,
                NestedSdJwtVcFixtures.EmployerFamilyNamePath
            }),
            $"Section 6.4: exactly the selected claim and the parent that carries it are revealed; the verifier saw [{Render(revealed)}].");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.TopLevelFamilyNamePath,
            revealed,
            "Section 6.4: the namesake at the root was never selected and must not reach the Verifier.");
        Assert.DoesNotContain(
            NestedSdJwtVcFixtures.TopLevelFamilyName,
            presentation,
            StringComparison.Ordinal,
            "Section 6.4: the unselected namesake's value must not appear on the wire at all.");
    }


    /// <summary>
    /// Proves the SD-CWT twin of the namesake case: one claim label occurring at two depths
    /// yields two disclosures at two positions. The CBOR profile mirrors
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>: "The Issuer
    /// MUST ensure that a new salt value is chosen for each claim, including when the same claim
    /// name occurs at different places in the structure of the SD-JWT."
    /// </summary>
    [TestMethod]
    public void SdCwtDisclosurePathsGiveEachNamesakeItsOwnPosition()
    {
        using SdToken<ReadOnlyMemory<byte>> token = MintNestedSdCwt();

        CredentialPath topLevel = CredentialPath.FromJsonPointer($"/{FamilyNameClaimKey}");
        CredentialPath nested = CredentialPath.FromJsonPointer($"/{EmployerClaimKey}/{FamilyNameClaimKey}");

        Assert.Contains(
            topLevel,
            token.DisclosurePaths.Paths,
            "Section 9.3: the top-level occurrence is a disclosure at the root map's path plus its label.");
        Assert.Contains(
            nested,
            token.DisclosurePaths.Paths,
            "Section 9.3: the occurrence one level down is a separate disclosure at its own containing map's path plus its label.");
        Assert.HasCount(2, token.DisclosurePaths.Paths, "Exactly the two namesakes are selectively disclosable.");
    }


    /// <summary>
    /// Proves the SD-CWT twin of the selection case: naming the nested namesake's position
    /// releases that disclosure and never its root-level namesake.
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below."
    /// </summary>
    [TestMethod]
    public void SdCwtSelectingTheNestedNamesakeReleasesThatDisclosureAlone()
    {
        using SdToken<ReadOnlyMemory<byte>> token = MintNestedSdCwt();

        CredentialPath topLevel = CredentialPath.FromJsonPointer($"/{FamilyNameClaimKey}");
        CredentialPath nested = CredentialPath.FromJsonPointer($"/{EmployerClaimKey}/{FamilyNameClaimKey}");

        SdDisclosureSelectionResult<ReadOnlyMemory<byte>> selection =
            token.SelectDisclosures(new HashSet<CredentialPath> { nested }, Pool);

        using SdToken<ReadOnlyMemory<byte>> presented = selection.Token;

        Assert.HasCount(1, presented.Disclosures, "Section 6.4: exactly the selected claim is sent.");
        Assert.Contains(nested, presented.DisclosurePaths.Paths, "The selected position is released.");
        Assert.DoesNotContain(
            topLevel,
            presented.DisclosurePaths.Paths,
            "Section 6.4: the namesake at the root was not selected and must not be released.");
        Assert.IsEmpty(selection.UnmatchedPaths, "A position the credential carries is never unmatched.");
    }


    /// <summary>
    /// Proves the SD-CWT issuance can make a claim disclosable below the root, so a credential it
    /// issues parses back. The CBOR profile mirrors
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 6</see>: "From this it
    /// follows that the _sd key containing digests MAY appear multiple times in an SD-JWT" — and
    /// Section 7.1 step 5 refuses what does not resolve: "If any Disclosure was not referenced by
    /// digest value in the Issuer-signed JWT (directly or recursively via other Disclosures), the
    /// SD-JWT MUST be rejected."
    /// </summary>
    [TestMethod]
    public async Task SdCwtIssuanceMakesAClaimBelowTheRootDisclosableAndTheCredentialParsesBack()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        using SdToken<ReadOnlyMemory<byte>> token = await MintNestedSdCwtThroughIssuanceAsync(
            privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(
            CredentialPath.FromJsonPointer($"/{EmployerClaimKey}/{FamilyNameClaimKey}"),
            token.DisclosurePaths.Paths,
            "Section 6: a redaction one level down must reach the wire as a redaction, so the disclosure it hides resolves at its own position.");
        Assert.Contains(
            CredentialPath.FromJsonPointer($"/{FamilyNameClaimKey}"),
            token.DisclosurePaths.Paths,
            "Section 6: the root-level redaction resolves at the root's path plus its label.");
    }


    /// <summary>
    /// Asserts that an array-element disclosure sits at <paramref name="expected"/> and carries
    /// <paramref name="value"/>.
    /// </summary>
    /// <param name="credential">The minted credential.</param>
    /// <param name="expected">The index position the specification assigns the element.</param>
    /// <param name="value">The element value the disclosure must hide.</param>
    private static void AssertElementAt(NestedSdJwtVcCredential credential, CredentialPath expected, string value)
    {
        bool isResolved = credential.Token.DisclosurePaths.TryGetDisclosure(expected, out SdDisclosure? disclosure);

        Assert.IsTrue(isResolved, $"Section 4.2.2: an element disclosure must resolve at '{expected}'.");
        Assert.IsNull(
            disclosure!.ClaimName,
            "Section 4.2.2: an array-element Disclosure is [salt, value] and carries no claim name.");
        Assert.AreEqual(
            value,
            disclosure.ClaimValue,
            $"Section 4.2.2: the marker at '{expected}' hides that element, decoys and undisclosed siblings counted in the index.");
    }


    /// <summary>
    /// Asserts a presented token released exactly <paramref name="expected"/> and no other
    /// disclosure.
    /// </summary>
    /// <typeparam name="TEnvelope">The token's envelope type.</typeparam>
    /// <param name="presented">The token the selection produced.</param>
    /// <param name="expected">The positions the selection must have released.</param>
    /// <param name="because">The clause and expectation the assertion carries.</param>
    private static void AssertReleased<TEnvelope>(
        SdToken<TEnvelope> presented,
        IReadOnlyList<CredentialPath> expected,
        string because) where TEnvelope : notnull
    {
        var released = new HashSet<CredentialPath>(presented.DisclosurePaths.Paths);

        Assert.IsTrue(
            released.SetEquals(new HashSet<CredentialPath>(expected)),
            $"{because} Released [{Render(released)}], expected [{Render(expected)}].");
        Assert.HasCount(
            expected.Count,
            presented.Disclosures,
            $"{because} One Disclosure per released position, each exactly once.");
    }


    /// <summary>
    /// Renders a set of positions as a readable list for an assertion message.
    /// </summary>
    /// <param name="paths">The positions to render.</param>
    /// <returns>The comma-separated JSON Pointer texts.</returns>
    private static string Render(IEnumerable<CredentialPath> paths)
    {
        return string.Join(", ", paths.Select(static path => path.ToString()));
    }


    /// <summary>
    /// Mints, by hand from RFC 9901 Section 4.2.1's disclosure format, a wire form whose
    /// top-level <c>_sd</c> array carries the digests of two object-property disclosures that
    /// bear the same claim name — the shape Section 7.1 step 3.c.ii.3 refuses.
    /// </summary>
    /// <returns>The malformed compact SD-JWT.</returns>
    private static string MintSameLevelDuplicateName()
    {
        SdDisclosure first = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            NestedSdJwtVcFixtures.FamilyNameClaim,
            NestedSdJwtVcFixtures.TopLevelFamilyName);
        SdDisclosure second = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            NestedSdJwtVcFixtures.FamilyNameClaim,
            NestedSdJwtVcFixtures.EmployerFamilyName);

        try
        {
            string firstEncoded = SdJwtSerializer.SerializeDisclosure(first, TestSetup.Base64UrlEncoder);
            string secondEncoded = SdJwtSerializer.SerializeDisclosure(second, TestSetup.Base64UrlEncoder);
            string firstDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
                firstEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            string secondDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
                secondEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

            string payloadJson = $$"""
            {
                "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
                "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
                "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
                "{{SdConstants.SdClaimName}}": ["{{firstDigest}}", "{{secondDigest}}"]
            }
            """;

            return NestedSdJwtVcFixtures.Compose(UnverifiableJws(payloadJson), [firstEncoded, secondEncoded]);
        }
        finally
        {
            first.Dispose();
            second.Dispose();
        }
    }


    /// <summary>
    /// Mints, by hand from RFC 9901 Section 4.2.1's disclosure format, a wire form carrying one
    /// disclosure the payload references and a second the payload does not — the shape Section
    /// 7.1 step 5 refuses.
    /// </summary>
    /// <returns>The malformed compact SD-JWT.</returns>
    private static string MintUnreferencedDisclosure()
    {
        SdDisclosure referenced = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            NestedSdJwtVcFixtures.FamilyNameClaim,
            NestedSdJwtVcFixtures.TopLevelFamilyName);
        SdDisclosure unreferenced = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            "given_name",
            "Erika");

        try
        {
            string referencedEncoded = SdJwtSerializer.SerializeDisclosure(referenced, TestSetup.Base64UrlEncoder);
            string unreferencedEncoded = SdJwtSerializer.SerializeDisclosure(unreferenced, TestSetup.Base64UrlEncoder);
            string referencedDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
                referencedEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

            string payloadJson = $$"""
            {
                "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
                "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
                "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
                "{{SdConstants.SdClaimName}}": ["{{referencedDigest}}"]
            }
            """;

            return NestedSdJwtVcFixtures.Compose(
                UnverifiableJws(payloadJson), [referencedEncoded, unreferencedEncoded]);
        }
        finally
        {
            referenced.Dispose();
            unreferenced.Dispose();
        }
    }


    /// <summary>
    /// Mints a wire form whose single Disclosure carries the given claim name, referenced by the
    /// root object's <c>_sd</c> array.
    /// </summary>
    /// <param name="claimName">The claim name the Disclosure carries.</param>
    /// <param name="claimValue">The Disclosure's claim value.</param>
    /// <returns>The compact SD-JWT.</returns>
    private static string MintDisclosureNamed(string claimName, string claimValue)
    {
        using SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool), claimName, claimValue);

        string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = $$"""
        {
            "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
            "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
            "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
            "{{SdConstants.SdClaimName}}": ["{{digest}}"]
        }
        """;

        return NestedSdJwtVcFixtures.Compose(UnverifiableJws(payloadJson), [encoded]);
    }


    /// <summary>
    /// Mints a wire form whose root object carries <c>family_name</c> in the clear AND an
    /// <c>_sd</c> digest resolving to a Disclosure of the same name — the collision RFC 9901
    /// Section 4.2.1's "or a claim name existing in the object as a permanently disclosed claim"
    /// forbids.
    /// </summary>
    /// <returns>The malformed compact SD-JWT.</returns>
    private static string MintDisclosureCollidingWithPlainSibling()
    {
        using SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            NestedSdJwtVcFixtures.FamilyNameClaim,
            NestedSdJwtVcFixtures.EmployerFamilyName);

        string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = $$"""
        {
            "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
            "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
            "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
            "{{NestedSdJwtVcFixtures.FamilyNameClaim}}": "{{NestedSdJwtVcFixtures.TopLevelFamilyName}}",
            "{{SdConstants.SdClaimName}}": ["{{digest}}"]
        }
        """;

        return NestedSdJwtVcFixtures.Compose(UnverifiableJws(payloadJson), [encoded]);
    }


    /// <summary>
    /// Mints a wire form whose root <c>_sd</c> array carries a legitimate digest string beside an
    /// integer — a value RFC 9901 Section 7.1 step 3.b.i's "an array of strings" does not admit.
    /// </summary>
    /// <returns>The compact SD-JWT whose <c>_sd</c> value identifies no digest.</returns>
    private static string MintSdArrayWithNonStringMember()
    {
        using SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            NestedSdJwtVcFixtures.FamilyNameClaim,
            NestedSdJwtVcFixtures.TopLevelFamilyName);

        string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = $$"""
        {
            "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
            "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
            "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
            "{{SdConstants.SdClaimName}}": ["{{digest}}", 42]
        }
        """;

        return NestedSdJwtVcFixtures.Compose(UnverifiableJws(payloadJson), [encoded]);
    }


    /// <summary>
    /// Mints an SD-CWT wire form whose single Disclosure carries its three-element array header in
    /// the non-minimal one-byte-argument form (<c>0x98 0x03</c> rather than <c>0x83</c>) — valid
    /// CBOR carrying the same three elements, but not the encoding
    /// <see cref="SdCwtSerializer.SerializeDisclosure(SdDisclosure, CborConformanceMode)"/> would
    /// write. The COSE_Sign1 is assembled here rather than through
    /// <see cref="SdCwtSerializer.Serialize(SdCwtMessage, CborConformanceMode)"/> so those exact
    /// bytes reach the wire.
    /// </summary>
    /// <returns>The COSE_Sign1 bytes.</returns>
    private static byte[] MintSdCwtWithNonMinimalArrayHeader()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            FamilyNameClaimKey.ToString(CultureInfo.InvariantCulture),
            NestedSdJwtVcFixtures.TopLevelFamilyName);

        byte[] disclosureBytes;
        try
        {
            byte[] canonical = SdCwtSerializer.SerializeDisclosure(disclosure);

            //The canonical form opens with 0x83 (array, three elements, argument in the initial
            //byte). The same array with a one-byte length argument is 0x98 0x03, which every CBOR
            //decoder reads identically and no canonical encoder would write.
            disclosureBytes = [0x98, 0x03, .. canonical.AsSpan(1)];
        }
        finally
        {
            disclosure.Dispose();
        }

        byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(disclosureBytes, WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);

        var payloadBuffer = new ArrayBufferWriter<byte>();
        var payloadWriter = new CborWriter(payloadBuffer, CborOptions.Lax);
        payloadWriter.WriteStartMap(3);
        payloadWriter.WriteInt32(WellKnownCwtClaimNames.Iss);
        payloadWriter.WriteTextString(NestedSdJwtVcFixtures.Issuer);
        payloadWriter.WriteInt32(WellKnownCwtClaimNames.Vct);
        payloadWriter.WriteTextString(NestedSdJwtVcFixtures.Vct);
        WriteRedactedClaimKeys(payloadWriter, digest);
        payloadWriter.WriteEndMap();

        return ComposeCoseSign1(payloadBuffer.WrittenSpan.ToArray(), disclosureBytes);
    }


    /// <summary>
    /// Mints an SD-CWT wire form whose claims map opens with a private claim keyed by a text
    /// string, ahead of the integer-keyed <c>iss</c> and <c>vct</c> that RFC 8392 registers.
    /// </summary>
    /// <returns>The COSE_Sign1 bytes.</returns>
    private static byte[] MintSdCwtWithLeadingTextKeyedClaim()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            FamilyNameClaimKey.ToString(CultureInfo.InvariantCulture),
            NestedSdJwtVcFixtures.TopLevelFamilyName);

        try
        {
            byte[] disclosureBytes = SdCwtSerializer.SerializeDisclosure(disclosure);
            byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(
                disclosureBytes, WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);

            var payloadBuffer = new ArrayBufferWriter<byte>();
            var payloadWriter = new CborWriter(payloadBuffer, CborOptions.Lax);
            payloadWriter.WriteStartMap(4);
            payloadWriter.WriteTextString("scheme");
            payloadWriter.WriteTextString("urn:example:private-claim");
            payloadWriter.WriteInt32(WellKnownCwtClaimNames.Iss);
            payloadWriter.WriteTextString(NestedSdJwtVcFixtures.Issuer);
            payloadWriter.WriteInt32(WellKnownCwtClaimNames.Vct);
            payloadWriter.WriteTextString(NestedSdJwtVcFixtures.Vct);
            WriteRedactedClaimKeys(payloadWriter, digest);
            payloadWriter.WriteEndMap();

            return ComposeCoseSign1(payloadBuffer.WrittenSpan.ToArray(), disclosureBytes);
        }
        finally
        {
            disclosure.Dispose();
        }
    }


    /// <summary>
    /// Assembles a COSE_Sign1 whose unprotected header carries the given Disclosure bytes verbatim,
    /// so a test can put an exact wire encoding in front of the parse.
    /// </summary>
    /// <param name="payload">The CWT claims map bytes the signature would cover.</param>
    /// <param name="disclosureBytes">The Disclosure's own CBOR bytes, carried as they are.</param>
    /// <returns>The COSE_Sign1 bytes.</returns>
    private static byte[] ComposeCoseSign1(byte[] payload, byte[] disclosureBytes)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteTag(new CborTag((ulong)CoseTags.Sign1));
        writer.WriteStartArray(4);
        writer.WriteByteString(UnverifiableCoseProtectedHeader.Span);
        writer.WriteStartMap(1);
        writer.WriteInt32(CoseHeaderParameters.SdClaims);
        writer.WriteStartArray(1);
        writer.WriteByteString(disclosureBytes);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteByteString(payload);
        writer.WriteByteString(UnverifiableCoseSignature.Span);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Mints the SD-CWT wire form whose root <c>redacted_claim_keys</c> entry resolves to a
    /// Disclosure claiming the <c>sd_claims</c> label as its own claim name.
    /// </summary>
    /// <returns>The COSE_Sign1 bytes carrying the malformed shape.</returns>
    private static byte[] MintSdCwtDisclosureNamedAfterAMechanismLabel()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool),
            SdCwtConstants.SdClaimsHeaderKey.ToString(CultureInfo.InvariantCulture),
            NestedSdJwtVcFixtures.TopLevelFamilyName);

        try
        {
            byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(
                SdCwtSerializer.SerializeDisclosure(disclosure), WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);

            var buffer = new ArrayBufferWriter<byte>();
            var writer = new CborWriter(buffer, CborOptions.Lax);
            writer.WriteStartMap(3);
            writer.WriteInt32(WellKnownCwtClaimNames.Iss);
            writer.WriteTextString(NestedSdJwtVcFixtures.Issuer);
            writer.WriteInt32(WellKnownCwtClaimNames.Vct);
            writer.WriteTextString(NestedSdJwtVcFixtures.Vct);
            WriteRedactedClaimKeys(writer, digest);
            writer.WriteEndMap();

            var message = new SdCwtMessage(
                buffer.WrittenSpan.ToArray(),
                UnverifiableCoseProtectedHeader,
                UnverifiableCoseSignature,
                [disclosure]);

            return SdCwtSerializer.Serialize(message);
        }
        finally
        {
            disclosure.Dispose();
        }
    }


    /// <summary>
    /// Mints, by hand from RFC 9901 Section 4.2.1's disclosure format, a wire form whose two
    /// Disclosures were built over the same salt bytes — the shape Section 9.3's "a new salt value
    /// is chosen for each claim" forbids. The names differ, so nothing but the salt collides.
    /// </summary>
    /// <returns>The malformed compact SD-JWT.</returns>
    private static string MintSharedSaltDisclosures()
    {
        byte[] saltBytes = Encoding.UTF8.GetBytes("one-salt-for-two-disclosures");

        SdDisclosure first = SdDisclosure.CreateProperty(
            TestSalts.FromBytes(saltBytes),
            NestedSdJwtVcFixtures.FamilyNameClaim,
            NestedSdJwtVcFixtures.TopLevelFamilyName);
        SdDisclosure second = SdDisclosure.CreateProperty(
            TestSalts.FromBytes(saltBytes),
            "given_name",
            "Erika");

        try
        {
            string firstEncoded = SdJwtSerializer.SerializeDisclosure(first, TestSetup.Base64UrlEncoder);
            string secondEncoded = SdJwtSerializer.SerializeDisclosure(second, TestSetup.Base64UrlEncoder);
            string firstDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
                firstEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            string secondDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
                secondEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

            string payloadJson = $$"""
            {
                "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
                "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
                "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
                "{{SdConstants.SdClaimName}}": ["{{firstDigest}}", "{{secondDigest}}"]
            }
            """;

            return NestedSdJwtVcFixtures.Compose(UnverifiableJws(payloadJson), [firstEncoded, secondEncoded]);
        }
        finally
        {
            first.Dispose();
            second.Dispose();
        }
    }


    /// <summary>
    /// Mints a wire form whose Disclosures form a chain of the requested length: each Disclosure's
    /// own value carries the <c>_sd</c> digest of the next, which is RFC 9901 Section 4.2.6's
    /// recursive-Disclosure construction taken to a depth no honest Issuer would mint. The chain is
    /// built from the innermost Disclosure outwards, since a Disclosure's digest depends on the
    /// value it carries.
    /// </summary>
    /// <param name="depth">How many Disclosures the chain carries.</param>
    /// <returns>The compact SD-JWT carrying the chain.</returns>
    private static string MintRecursiveDisclosureChain(int depth)
    {
        var encodedDisclosures = new List<string>(depth);
        string innerDigest = string.Empty;

        for(int level = 0; level < depth; level++)
        {
            string claimValueJson = level == 0
                ? "\"leaf\""
                : $$"""{"{{SdConstants.SdClaimName}}": ["{{innerDigest}}"]}""";

            using JsonDocument document = JsonDocument.Parse(claimValueJson);
            using SdDisclosure disclosure = SdDisclosure.CreateProperty(
                TestSalts.FromBytes(Encoding.UTF8.GetBytes($"salt-level-{level}")),
                $"level_{level}",
                document.RootElement);

            string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
            encodedDisclosures.Add(encoded);
            innerDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
                encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        }

        string payloadJson = $$"""
        {
            "{{SdConstants.SdAlgorithmClaimName}}": "{{WellKnownHashAlgorithms.Sha256Iana}}",
            "{{WellKnownJwtClaimNames.Vct}}": "{{NestedSdJwtVcFixtures.Vct}}",
            "{{WellKnownJwtClaimNames.Iss}}": "{{NestedSdJwtVcFixtures.Issuer}}",
            "{{SdConstants.SdClaimName}}": ["{{innerDigest}}"]
        }
        """;

        return NestedSdJwtVcFixtures.Compose(UnverifiableJws(payloadJson), encodedDisclosures);
    }


    /// <summary>
    /// Builds a compact JWS whose signature segment is zero bytes. The parse under test reads the
    /// payload's digest structure and never checks the signature, so a malformed-payload case
    /// needs no issuer key; the end-to-end test signs for real.
    /// </summary>
    /// <param name="payloadJson">The JWT claims set to carry.</param>
    /// <returns>The three-segment compact serialization.</returns>
    private static string UnverifiableJws(string payloadJson)
    {
        string header = /*lang=json,strict*/ """{"alg":"ES256","typ":"dc+sd-jwt"}""";
        string headerSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header));
        string payloadSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        string signatureSegment = TestSetup.Base64UrlEncoder(new byte[64]);

        return $"{headerSegment}.{payloadSegment}.{signatureSegment}";
    }


    /// <summary>
    /// Mints the SD-CWT twin from the CBOR profile's own redaction shape: one claim label carried
    /// both at the root of the claims map and inside a nested map, each behind a
    /// <c>redacted_claim_keys</c> entry keyed by CBOR <c>simple(59)</c> at its own level. The
    /// signature is not checked by the parse under test, so the envelope carries a placeholder
    /// one; the end-to-end SD-JWT test signs for real.
    /// </summary>
    /// <returns>The parsed SD-CWT. The caller disposes it.</returns>
    private static SdToken<ReadOnlyMemory<byte>> MintNestedSdCwt()
    {
        string claimLabel = FamilyNameClaimKey.ToString(CultureInfo.InvariantCulture);

        SdDisclosure topLevel = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool), claimLabel, NestedSdJwtVcFixtures.TopLevelFamilyName);
        SdDisclosure nested = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, Pool), claimLabel, NestedSdJwtVcFixtures.EmployerFamilyName);

        try
        {
            byte[] topLevelDigest = SdCwtSerializer.ComputeDisclosureDigest(
                SdCwtSerializer.SerializeDisclosure(topLevel), WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);
            byte[] nestedDigest = SdCwtSerializer.ComputeDisclosureDigest(
                SdCwtSerializer.SerializeDisclosure(nested), WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);

            var message = new SdCwtMessage(
                BuildNestedSdCwtPayload(topLevelDigest, nestedDigest),
                UnverifiableCoseProtectedHeader,
                UnverifiableCoseSignature,
                [topLevel, nested]);

            byte[] wireBytes = SdCwtSerializer.Serialize(message);

            return SdCwtSerializer.ParseToken(wireBytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder);
        }
        finally
        {
            topLevel.Dispose();
            nested.Dispose();
        }
    }


    /// <summary>
    /// Writes the CWT claims map the SD-CWT twin is minted from: the always-disclosed issuer and
    /// type labels, a nested map whose only entry is its own <c>redacted_claim_keys</c> array, and
    /// the root's <c>redacted_claim_keys</c> array — a redaction at two levels, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 6</see> admits: "the
    /// _sd key containing digests MAY appear multiple times in an SD-JWT".
    /// </summary>
    /// <param name="topLevelDigest">The digest of the root-level disclosure.</param>
    /// <param name="nestedDigest">The digest of the disclosure one level down.</param>
    /// <returns>The CBOR claims map.</returns>
    private static byte[] BuildNestedSdCwtPayload(byte[] topLevelDigest, byte[] nestedDigest)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteStartMap(4);

        writer.WriteInt32(WellKnownCwtClaimNames.Iss);
        writer.WriteTextString(NestedSdJwtVcFixtures.Issuer);

        writer.WriteInt32(WellKnownCwtClaimNames.Vct);
        writer.WriteTextString(NestedSdJwtVcFixtures.Vct);

        writer.WriteInt32(EmployerClaimKey);
        writer.WriteStartMap(1);
        WriteRedactedClaimKeys(writer, nestedDigest);
        writer.WriteEndMap();

        WriteRedactedClaimKeys(writer, topLevelDigest);

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Writes one <c>redacted_claim_keys</c> map entry: the CBOR <c>simple(59)</c> key and a
    /// single-digest array under it.
    /// </summary>
    /// <param name="writer">The writer, positioned inside a map.</param>
    /// <param name="digest">The digest the entry hides.</param>
    private static void WriteRedactedClaimKeys(CborWriter writer, byte[] digest)
    {
        writer.WriteSimpleValue(SdCwtConstants.RedactedClaimKeysSimpleValue);
        writer.WriteStartArray(1);
        writer.WriteByteString(digest);
        writer.WriteEndArray();
    }


    /// <summary>
    /// Mints the SD-CWT through the library's own SD-CWT issuance: one claim label carried both at
    /// the root of the claims map and inside a nested map, both named as selectively disclosable,
    /// then rebuilt into its full wire form and parsed back so the token carries resolved
    /// positions.
    /// </summary>
    /// <param name="issuerPrivateKey">The issuer's signing key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed SD-CWT. The caller disposes it.</returns>
    private static async ValueTask<SdToken<ReadOnlyMemory<byte>>> MintNestedSdCwtThroughIssuanceAsync(
        PrivateKeyMemory issuerPrivateKey,
        CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = NestedSdJwtVcFixtures.Issuer,
            [WellKnownCwtClaimNames.Vct] = NestedSdJwtVcFixtures.Vct,
            [FamilyNameClaimKey] = NestedSdJwtVcFixtures.TopLevelFamilyName,
            [EmployerClaimKey] = new Dictionary<int, object>
            {
                [FamilyNameClaimKey] = NestedSdJwtVcFixtures.EmployerFamilyName
            }
        };

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{FamilyNameClaimKey}"),
            CredentialPath.FromJsonPointer($"/{EmployerClaimKey}/{FamilyNameClaimKey}")
        };

        SdToken<ReadOnlyMemory<byte>> issued = await claims.IssueSdCwtTokenAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap,
            SdCwtIssuance.IssueVerboseAsync,
            disclosablePaths,
            TestSalts.DefaultGenerator(),
            issuerPrivateKey,
            SdCwtIssuerKeyId,
            Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using(issued)
        {
            SdCwtMessage bare = SdCwtSerializer.Parse(issued.IssuerSigned, TestSalts.TestSaltTag, Pool);
            var full = new SdCwtMessage(bare.Payload, bare.ProtectedHeader, bare.Signature, issued.Disclosures);
            byte[] wireBytes = SdCwtSerializer.Serialize(full);

            return SdCwtSerializer.ParseToken(wireBytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder);
        }
    }
}
