using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A minted SD-JWT VC together with the compact wire form it was minted from and the parsed
/// token the holder works with.
/// </summary>
/// <remarks>
/// <para>
/// The compact form and the token are the same credential seen from the two sides a holder
/// handles: the string it stores and the <see cref="SdToken{TEnvelope}"/> a parse produced from
/// it. Disposing this disposes the token (and therefore every disclosure and salt it owns).
/// </para>
/// </remarks>
internal sealed class NestedSdJwtVcCredential: IDisposable
{
    /// <summary>The compact SD-JWT: the issuer-signed JWS followed by every disclosure, tilde-separated.</summary>
    public string CompactSdJwt { get; }

    /// <summary>The credential parsed back from <see cref="CompactSdJwt"/>, carrying resolved positions.</summary>
    public SdToken<string> Token { get; }


    /// <summary>
    /// Creates the pair, taking ownership of <paramref name="token"/>.
    /// </summary>
    /// <param name="compactSdJwt">The compact wire form.</param>
    /// <param name="token">The token parsed from <paramref name="compactSdJwt"/>.</param>
    internal NestedSdJwtVcCredential(string compactSdJwt, SdToken<string> token)
    {
        CompactSdJwt = compactSdJwt;
        Token = token;
    }


    /// <summary>Disposes the parsed token and every disclosure it owns.</summary>
    public void Dispose()
    {
        Token.Dispose();
    }
}


/// <summary>
/// Mints an SD-JWT VC whose selectively disclosable claims sit at every position
/// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> admits: a top-level claim,
/// a claim of the same name one level down, array elements addressed by index, and members of a
/// recursively disclosable object.
/// </summary>
/// <remarks>
/// <para>
/// The shape is the specification's own. The namesake pair is the case RFC 9901 Section 9.3
/// names — "The Issuer MUST ensure that a new salt value is chosen for each claim, including
/// when the same claim name occurs at different places in the structure of the SD-JWT." The
/// <c>nationalities</c> array is Section 4.2.6's recursive-disclosure example (<c>DE</c>,
/// <c>FR</c>, <c>UK</c>), preceded by a decoy marker so an element's index is the index of the
/// marker as issued rather than the index it would take after Section 7.1 step 3.d removes what
/// was not disclosed. The <c>address</c> members are Section 6's nested-data example
/// (<c>Schulstr. 12</c>, <c>Schulpforta</c>, <c>Sachsen-Anhalt</c>, <c>DE</c>). The always
/// disclosed <c>vct</c>, <c>iss</c> and <c>aka_vcts</c> are the SD-JWT VC evidence claims of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC
/// Section 2.2.2.1 to 2.2.2.3</see>.
/// </para>
/// <para>
/// The credential is produced through the library's own issuance
/// (<see cref="SdJwtIssuanceExtensions"/> over <see cref="SdJwtIssuance.IssueVerboseAsync"/>,
/// <see cref="TestSalts"/>, <see cref="TestSetup.Base64UrlEncoder"/>): the issuance makes the
/// four root-level claims disclosable and signs, while the digests that sit inside those
/// claims' own values — the nested namesake, the array elements, the address members — are
/// placed into the payload beforehand, which is exactly the layering RFC 9901 Section 4.2.6
/// describes ("first making the entries within the ... array selectively disclosable, and then
/// making the whole ... field selectively disclosable").
/// </para>
/// <para>
/// The expected path of every disclosure is stated here as a literal, read off the
/// specification's rules rather than from what the parse produced, so a test comparing against
/// it compares against the specification.
/// </para>
/// <para>
/// <see cref="MintDeterministicIdentityCredential"/> and <see cref="MintDeterministicSdCwtCredential"/>
/// hand-build their wire forms with a placeholder signature, exercising a claims adapter over a
/// structure rather than signature verification; they additionally carry the
/// <c>age_equal_or_over</c>/<c>age_in_years</c> claims of the SD-JWT VC payload example and an
/// always-disclosed <c>evidence</c> array. <see cref="MintHolderBoundCredentialAsync"/> and
/// <see cref="MintHolderBoundSdCwtCredentialAsync"/> issue for real, under a holder's <c>cnf</c>
/// confirmation key, over a plain (non-recursive) <c>employer</c> object whose <c>family_name</c>
/// member is disclosed directly beside an always-disclosed <c>name</c> sibling — the position RFC
/// 9901 Section 9.3's namesake-at-depth rule reaches without a digested container.
/// </para>
/// </remarks>
[SuppressMessage(
    "Reliability", "CA2000",
    Justification =
        "The minting helpers construct Salt instances and hand them to SdDisclosure factory " +
        "methods that take ownership, and the disclosures themselves are disposed in the " +
        "finally block once their wire text has been read (the parsed token owns its own " +
        "freshly constructed copies). The analyzer cannot see ownership transfer through " +
        "factory methods. The same holds for the deterministic and holder-bound minters: their " +
        "disclosures and issuer keys are disposed inside the method that constructs them, or " +
        "ownership passes to the caller through the returned token/key.")]
internal static class NestedSdJwtVcFixtures
{
    /// <summary>The credential's type, the <c>vct</c> claim of SD-JWT VC Section 2.2.2.1.</summary>
    public const string Vct = "https://credentials.example.com/identity_credential";

    /// <summary>The credential's issuer, the <c>iss</c> claim of SD-JWT VC Section 2.2.2.3.</summary>
    public const string Issuer = "https://issuer.example.com";

    /// <summary>The single additional type carried in <c>aka_vcts</c> (SD-JWT VC Section 2.2.2.2).</summary>
    public const string AdditionalVct = "https://credentials.example.com/pid";

    /// <summary>The <c>kid</c> the issuer signs under.</summary>
    public const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>The top-level <c>family_name</c> value, RFC 9901 Section 4.2.6's.</summary>
    public const string TopLevelFamilyName = "Möbius";

    /// <summary>The <c>family_name</c> value one level down, distinct so a release is attributable.</summary>
    public const string EmployerFamilyName = "Mustermann";

    /// <summary>The first nationality, RFC 9901 Section 4.2.6's.</summary>
    public const string FirstNationality = "DE";

    /// <summary>The second nationality, RFC 9901 Section 4.2.6's.</summary>
    public const string SecondNationality = "FR";

    /// <summary>The third nationality, RFC 9901 Section 4.2.6's.</summary>
    public const string ThirdNationality = "UK";

    /// <summary>The address street, RFC 9901 Section 6's.</summary>
    public const string StreetAddress = "Schulstr. 12";

    /// <summary>The address locality, RFC 9901 Section 6's.</summary>
    public const string Locality = "Schulpforta";

    /// <summary>The address region, RFC 9901 Section 6's — a member of the address that is not disclosable.</summary>
    public const string Region = "Sachsen-Anhalt";

    /// <summary>The address country, RFC 9901 Section 6's.</summary>
    public const string Country = "DE";

    /// <summary>The <c>family_name</c> claim name, borne by two disclosures at two positions.</summary>
    public const string FamilyNameClaim = "family_name";

    /// <summary>The claim name of the recursively disclosable employer object.</summary>
    public const string EmployerClaim = "employer";

    /// <summary>The claim name of the recursively disclosable nationalities array.</summary>
    public const string NationalitiesClaim = "nationalities";

    /// <summary>The claim name of the recursively disclosable address object.</summary>
    public const string AddressClaim = "address";

    /// <summary>
    /// The single entry of <see cref="MintDeterministicIdentityCredential"/>'s <c>aka_vcts</c>
    /// claim — distinct from <see cref="AdditionalVct"/>, which belongs to <see cref="MintAsync"/>'s
    /// shape.
    /// </summary>
    public const string DeterministicIdentityAdditionalVct = "urn:example:eudi:pid";

    /// <summary>
    /// The top-level <c>family_name</c> value <see cref="MintHolderBoundCredentialAsync"/> and
    /// <see cref="MintHolderBoundSdCwtCredentialAsync"/> issue, distinct from
    /// <see cref="TopLevelFamilyName"/>, which belongs to <see cref="MintAsync"/>'s shape.
    /// </summary>
    public const string SubjectFamilyName = "Mustermann";

    /// <summary>
    /// The <c>employer.family_name</c> value <see cref="MintHolderBoundCredentialAsync"/> and
    /// <see cref="MintHolderBoundSdCwtCredentialAsync"/> issue — a distinct name from
    /// <see cref="EmployerFamilyName"/> is needed because the two minters carry different values
    /// at the same claim name (<see cref="EmployerFamilyName"/> is <c>MintAsync</c>'s own).
    /// </summary>
    public const string HolderBoundEmployerFamilyName = "Schmidt";

    /// <summary>
    /// The employer's own always-disclosed <c>name</c>, the sibling
    /// <see cref="HolderBoundEmployerFamilyName"/> sits beside in a plain (non-recursive)
    /// <c>employer</c> object.
    /// </summary>
    public const string EmployerName = "Beispiel AG";

    /// <summary>The additional type <see cref="MintHolderBoundCredentialAsync"/> declares via <c>aka_vcts</c> when it is issued with a type.</summary>
    public const string HolderBoundAdditionalVct = "https://credentials.example.com/person_credential";

    /// <summary>The top-level disclosure's JSON Pointer text, as <see cref="MintHolderBoundCredentialAsync"/>'s disclosable-paths set takes it.</summary>
    public const string TopLevelFamilyNamePointer = "/family_name";

    /// <summary>The nested disclosure's JSON Pointer text, as <see cref="MintHolderBoundCredentialAsync"/>'s disclosable-paths set takes it.</summary>
    public const string NestedFamilyNamePointer = "/employer/family_name";

    /// <summary>The SD-CWT twin's top-level claim label, standing in for <c>family_name</c>.</summary>
    public const int CwtClaimKeyFamilyName = 101;

    /// <summary>The SD-CWT twin's <c>employer</c> map label.</summary>
    public const int CwtClaimKeyEmployer = 500;

    /// <summary>The SD-CWT twin's <c>name</c> label inside the <c>employer</c> map.</summary>
    public const int CwtClaimKeyEmployerName = 502;

    /// <summary><see href="https://www.rfc-editor.org/rfc/rfc8747#section-3.1">RFC 8747 Section 3.1</see>: the <c>cnf</c> confirmation map carries the COSE_Key under member 1.</summary>
    public const int CnfCoseKeyMember = 1;

    /// <summary>The SD-CWT top-level disclosure's JSON Pointer text: the root claims map plus the claim label.</summary>
    public const string CwtTopLevelFamilyNamePointer = "/101";

    /// <summary>The SD-CWT nested disclosure's JSON Pointer text: the <c>employer</c> map's path plus the claim label.</summary>
    public const string CwtNestedFamilyNamePointer = "/500/101";


    /// <summary>The top-level namesake's position: the root object's path plus its name.</summary>
    public static CredentialPath TopLevelFamilyNamePath => CredentialPath.FromJsonPointer("/family_name");

    /// <summary>The recursively disclosable employer object's position.</summary>
    public static CredentialPath EmployerPath => CredentialPath.FromJsonPointer("/employer");

    /// <summary>The nested namesake's position: its containing object's path plus its name.</summary>
    public static CredentialPath EmployerFamilyNamePath => CredentialPath.FromJsonPointer("/employer/family_name");

    /// <summary>The recursively disclosable nationalities array's position.</summary>
    public static CredentialPath NationalitiesPath => CredentialPath.FromJsonPointer("/nationalities");

    /// <summary>The decoy marker occupies index 0, so the first disclosed nationality is index 1.</summary>
    public static CredentialPath FirstNationalityPath => CredentialPath.FromJsonPointer("/nationalities/1");

    /// <summary>The second disclosed nationality's position.</summary>
    public static CredentialPath SecondNationalityPath => CredentialPath.FromJsonPointer("/nationalities/2");

    /// <summary>The third disclosed nationality's position.</summary>
    public static CredentialPath ThirdNationalityPath => CredentialPath.FromJsonPointer("/nationalities/3");

    /// <summary>The recursively disclosable address object's position.</summary>
    public static CredentialPath AddressPath => CredentialPath.FromJsonPointer("/address");

    /// <summary>The address street member's position, running through its parent.</summary>
    public static CredentialPath StreetAddressPath => CredentialPath.FromJsonPointer("/address/street_address");

    /// <summary>The address locality member's position, running through its parent.</summary>
    public static CredentialPath LocalityPath => CredentialPath.FromJsonPointer("/address/locality");

    /// <summary>The address country member's position, running through its parent.</summary>
    public static CredentialPath CountryPath => CredentialPath.FromJsonPointer("/address/country");

    /// <summary>The always disclosed type claim's position.</summary>
    public static CredentialPath VctPath => CredentialPath.FromJsonPointer("/vct");

    /// <summary>The always disclosed issuer claim's position.</summary>
    public static CredentialPath IssuerPath => CredentialPath.FromJsonPointer("/iss");

    /// <summary>The always disclosed additional-types claim's position.</summary>
    public static CredentialPath AkaVctsPath => CredentialPath.FromJsonPointer("/aka_vcts");


    /// <summary>
    /// Every position a disclosure occupies in the minted credential, stated from the
    /// specification's rules.
    /// </summary>
    public static IReadOnlySet<CredentialPath> ExpectedDisclosurePaths { get; } = new HashSet<CredentialPath>
    {
        TopLevelFamilyNamePath,
        EmployerPath,
        EmployerFamilyNamePath,
        NationalitiesPath,
        FirstNationalityPath,
        SecondNationalityPath,
        ThirdNationalityPath,
        AddressPath,
        StreetAddressPath,
        LocalityPath,
        CountryPath
    };


    /// <summary>
    /// The first disclosed nationality's position in <see cref="MintDeterministicIdentityCredential"/>'s
    /// array — index 0, since that credential's decoy marker occupies the LAST position rather than
    /// the first (the opposite arrangement from <see cref="MintAsync"/>'s shape).
    /// </summary>
    public static CredentialPath DeterministicFirstNationalityPath => CredentialPath.FromJsonPointer("/nationalities/0");

    /// <summary>The second disclosed nationality's position in <see cref="MintDeterministicIdentityCredential"/>'s array.</summary>
    public static CredentialPath DeterministicSecondNationalityPath => CredentialPath.FromJsonPointer("/nationalities/1");

    /// <summary>The third disclosed nationality's position in <see cref="MintDeterministicIdentityCredential"/>'s array.</summary>
    public static CredentialPath DeterministicThirdNationalityPath => CredentialPath.FromJsonPointer("/nationalities/2");

    /// <summary>The recursively disclosable <c>age_equal_or_over</c> object's position.</summary>
    public static CredentialPath AgeEqualOrOverPath => CredentialPath.FromJsonPointer("/age_equal_or_over");

    /// <summary>The <c>18</c> member's position under the recursively disclosable <c>age_equal_or_over</c> object.</summary>
    public static CredentialPath AgeOver18Path => CredentialPath.FromJsonPointer("/age_equal_or_over/18");

    /// <summary>The <c>65</c> member's position under the recursively disclosable <c>age_equal_or_over</c> object.</summary>
    public static CredentialPath AgeOver65Path => CredentialPath.FromJsonPointer("/age_equal_or_over/65");

    /// <summary>The top-level <c>age_in_years</c> disclosure's position.</summary>
    public static CredentialPath AgeInYearsPath => CredentialPath.FromJsonPointer("/age_in_years");


    /// <summary>
    /// Every position a disclosure occupies in <see cref="MintDeterministicIdentityCredential"/>'s
    /// credential, stated from the specification's rules — the same top-level namesake, nested
    /// namesake, nationalities array and address positions <see cref="ExpectedDisclosurePaths"/>
    /// states for <see cref="MintAsync"/>'s shape, plus the <c>age_equal_or_over</c>/<c>age_in_years</c>
    /// positions this shape alone carries.
    /// </summary>
    public static IReadOnlySet<CredentialPath> IdentityCredentialExpectedDisclosurePaths { get; } = new HashSet<CredentialPath>
    {
        TopLevelFamilyNamePath,
        EmployerPath,
        EmployerFamilyNamePath,
        DeterministicFirstNationalityPath,
        DeterministicSecondNationalityPath,
        DeterministicThirdNationalityPath,
        AddressPath,
        StreetAddressPath,
        LocalityPath,
        CountryPath,
        AgeEqualOrOverPath,
        AgeOver18Path,
        AgeOver65Path,
        AgeInYearsPath
    };


    /// <summary>The root-level claims the issuance makes selectively disclosable.</summary>
    private static IReadOnlySet<CredentialPath> RootDisclosablePaths { get; } = new HashSet<CredentialPath>
    {
        TopLevelFamilyNamePath,
        EmployerPath,
        NationalitiesPath,
        AddressPath
    };


    /// <summary>
    /// Mints the credential and parses it back, so the returned token carries the positions the
    /// walk resolved.
    /// </summary>
    /// <param name="issuerPrivateKey">The issuer's signing key.</param>
    /// <param name="pool">The memory pool every salt and buffer is rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact wire form and the parsed token. The caller disposes the result.</returns>
    public static async ValueTask<NestedSdJwtVcCredential> MintAsync(
        PrivateKeyMemory issuerPrivateKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuerPrivateKey);
        ArgumentNullException.ThrowIfNull(pool);

        var innerDisclosures = new List<SdDisclosure>();
        var innerWire = new List<string>();

        try
        {
            string employerFamilyNameDigest = AddProperty(innerDisclosures, innerWire, pool, FamilyNameClaim, EmployerFamilyName);
            string firstNationalityDigest = AddArrayElement(innerDisclosures, innerWire, pool, FirstNationality);
            string secondNationalityDigest = AddArrayElement(innerDisclosures, innerWire, pool, SecondNationality);
            string thirdNationalityDigest = AddArrayElement(innerDisclosures, innerWire, pool, ThirdNationality);
            string streetAddressDigest = AddProperty(innerDisclosures, innerWire, pool, "street_address", StreetAddress);
            string localityDigest = AddProperty(innerDisclosures, innerWire, pool, "locality", Locality);
            string countryDigest = AddProperty(innerDisclosures, innerWire, pool, "country", Country);
            string decoyDigest = DecoyDigest(pool);

            string payloadJson = $$"""
            {
                "{{WellKnownJwtClaimNames.Vct}}": "{{Vct}}",
                "{{WellKnownJwtClaimNames.Iss}}": "{{Issuer}}",
                "{{WellKnownJwtClaimNames.AkaVcts}}": ["{{AdditionalVct}}"],
                "{{FamilyNameClaim}}": "{{TopLevelFamilyName}}",
                "{{EmployerClaim}}": {
                    "{{SdConstants.SdClaimName}}": ["{{employerFamilyNameDigest}}"]
                },
                "{{NationalitiesClaim}}": [
                    {"{{SdConstants.ArrayDigestKey}}": "{{decoyDigest}}"},
                    {"{{SdConstants.ArrayDigestKey}}": "{{firstNationalityDigest}}"},
                    {"{{SdConstants.ArrayDigestKey}}": "{{secondNationalityDigest}}"},
                    {"{{SdConstants.ArrayDigestKey}}": "{{thirdNationalityDigest}}"}
                ],
                "{{AddressClaim}}": {
                    "region": "{{Region}}",
                    "{{SdConstants.SdClaimName}}": ["{{streetAddressDigest}}", "{{localityDigest}}", "{{countryDigest}}"]
                }
            }
            """;

            SdTokenResult issued = await payloadJson.IssueSdJwtAsync(
                static (string json) => Encoding.UTF8.GetBytes(json),
                SdJwtIssuance.IssueVerboseAsync,
                RootDisclosablePaths,
                TestSalts.DefaultGenerator(),
                issuerPrivateKey,
                IssuerKeyId,
                pool,
                mediaType: WellKnownMediaTypes.Jwt.DcSdJwt,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            string compactSdJwt;
            try
            {
                var wire = new List<string>(issued.Disclosures.Count + innerWire.Count);
                foreach(SdDisclosure disclosure in issued.Disclosures)
                {
                    wire.Add(SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder));
                }

                wire.AddRange(innerWire);
                compactSdJwt = Compose(Encoding.UTF8.GetString(issued.SignedToken.Span), wire);
            }
            finally
            {
                foreach(SdDisclosure disclosure in issued.Disclosures)
                {
                    disclosure.Dispose();
                }
            }

            SdToken<string> token = SdJwtSerializer.ParseToken(
                compactSdJwt,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                pool,
                TestSalts.TestSaltTag);

            return new NestedSdJwtVcCredential(compactSdJwt, token);
        }
        finally
        {
            foreach(SdDisclosure disclosure in innerDisclosures)
            {
                disclosure.Dispose();
            }
        }
    }


    /// <summary>
    /// Assembles a compact SD-JWT: the issuer-signed JWS, then every disclosure, each followed
    /// by the tilde separator RFC 9901 Section 4 defines.
    /// </summary>
    /// <param name="issuerJws">The issuer-signed compact JWS.</param>
    /// <param name="encodedDisclosures">The base64url-encoded disclosures, in wire order.</param>
    /// <returns>The compact SD-JWT.</returns>
    public static string Compose(string issuerJws, IReadOnlyList<string> encodedDisclosures)
    {
        ArgumentNullException.ThrowIfNull(issuerJws);
        ArgumentNullException.ThrowIfNull(encodedDisclosures);

        var builder = new StringBuilder(issuerJws);
        builder.Append(SdConstants.JwtSeparator);

        foreach(string encoded in encodedDisclosures)
        {
            builder.Append(encoded);
            builder.Append(SdConstants.JwtSeparator);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Creates an object-property disclosure (RFC 9901 Section 4.2.1's three-element array),
    /// records it and its wire text, and returns the digest the payload must carry for it.
    /// </summary>
    /// <param name="disclosures">Accumulates the created disclosure for disposal.</param>
    /// <param name="encodedDisclosures">Accumulates the disclosure's wire text.</param>
    /// <param name="pool">The pool the salt is rented from.</param>
    /// <param name="claimName">The claim name, local to its containing object.</param>
    /// <param name="claimValue">The claim value.</param>
    /// <returns>The base64url-encoded digest of the disclosure's wire text.</returns>
    private static string AddProperty(
        List<SdDisclosure> disclosures,
        List<string> encodedDisclosures,
        BaseMemoryPool pool,
        string claimName,
        string claimValue)
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.Generate(TestSalts.TestSaltTag, pool), claimName, claimValue);
        disclosures.Add(disclosure);

        return Record(encodedDisclosures, disclosure);
    }


    /// <summary>
    /// Creates an array-element disclosure (RFC 9901 Section 4.2.2's two-element array, which
    /// carries no name), records it and its wire text, and returns the digest the payload's
    /// marker must carry for it.
    /// </summary>
    /// <param name="disclosures">Accumulates the created disclosure for disposal.</param>
    /// <param name="encodedDisclosures">Accumulates the disclosure's wire text.</param>
    /// <param name="pool">The pool the salt is rented from.</param>
    /// <param name="elementValue">The array element that is to be hidden.</param>
    /// <returns>The base64url-encoded digest of the disclosure's wire text.</returns>
    private static string AddArrayElement(
        List<SdDisclosure> disclosures,
        List<string> encodedDisclosures,
        BaseMemoryPool pool,
        string elementValue)
    {
        SdDisclosure disclosure = SdDisclosure.CreateArrayElement(
            TestSalts.Generate(TestSalts.TestSaltTag, pool), elementValue);
        disclosures.Add(disclosure);

        return Record(encodedDisclosures, disclosure);
    }


    /// <summary>
    /// Serializes a disclosure, records its wire text and returns its digest — the digest is
    /// computed over the base64url-encoded disclosure exactly as it goes on the wire, per RFC
    /// 9901 Section 4.2.3.
    /// </summary>
    /// <param name="encodedDisclosures">Accumulates the disclosure's wire text.</param>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <returns>The base64url-encoded digest.</returns>
    private static string Record(List<string> encodedDisclosures, SdDisclosure disclosure)
    {
        string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
        encodedDisclosures.Add(encoded);

        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Produces a decoy digest (RFC 9901 Section 4.2.5): a digest over random bytes that no
    /// disclosure backs, so the marker carrying it is never resolvable while still occupying its
    /// position in the array.
    /// </summary>
    /// <param name="pool">The pool the random bytes are rented from.</param>
    /// <returns>The base64url-encoded decoy digest.</returns>
    private static string DecoyDigest(BaseMemoryPool pool)
    {
        using Salt decoySalt = TestSalts.Generate(TestSalts.TestSaltTag, pool);
        string encoded = TestSetup.Base64UrlEncoder(decoySalt.AsReadOnlySpan());

        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Hand-builds the compact SD-JWT wire form: always-disclosed <c>vct</c>, <c>iss</c> and
    /// <c>aka_vcts</c>; a top-level <c>family_name</c> disclosure and a namesake nested under the
    /// recursively disclosable <c>employer</c>; the <c>nationalities</c> array of RFC 9901 Section
    /// 4.2.6 with three element disclosures and a decoy marker at the LAST position; the
    /// <c>address</c> object of RFC 9901 Section 6 with disclosable members; and the
    /// <c>age_equal_or_over</c> object and <c>age_in_years</c> claim of the SD-JWT VC payload
    /// example, carrying the boolean and integer claim values. The signature is not exercised —
    /// this credential is only ever walked structurally, never cryptographically verified.
    /// </summary>
    /// <returns>The compact SD-JWT: the issuer-signed JWS followed by every disclosure.</returns>
    public static string MintDeterministicIdentityCredential()
    {
        (string Encoded, string Digest) familyName = EncodeProperty("salt-family-name", "family_name", "\"M\\u00f6bius\"");
        (string Encoded, string Digest) employerFamilyName = EncodeProperty("salt-employer-family-name", "family_name", "\"Mustermann\"");
        (string Encoded, string Digest) employer = EncodeProperty(
            "salt-employer", "employer", $$"""{"_sd": ["{{employerFamilyName.Digest}}"]}""");

        (string Encoded, string Digest) streetAddress = EncodeProperty("salt-street-address", "street_address", "\"Schulstr. 12\"");
        (string Encoded, string Digest) locality = EncodeProperty("salt-locality", "locality", "\"Schulpforta\"");
        (string Encoded, string Digest) country = EncodeProperty("salt-country", "country", "\"DE\"");
        (string Encoded, string Digest) address = EncodeProperty(
            "salt-address",
            "address",
            $$"""{"_sd": ["{{streetAddress.Digest}}", "{{locality.Digest}}", "{{country.Digest}}"]}""");

        (string Encoded, string Digest) ageOver18 = EncodeProperty("salt-age-18", "18", "true");
        (string Encoded, string Digest) ageOver65 = EncodeProperty("salt-age-65", "65", "false");
        (string Encoded, string Digest) ageEqualOrOver = EncodeProperty(
            "salt-age-equal-or-over",
            "age_equal_or_over",
            $$"""{"_sd": ["{{ageOver18.Digest}}", "{{ageOver65.Digest}}"]}""");
        (string Encoded, string Digest) ageInYears = EncodeProperty("salt-age-in-years", "age_in_years", "62");

        (string Encoded, string Digest) germany = EncodeArrayElement("salt-nationality-de", "\"DE\"");
        (string Encoded, string Digest) france = EncodeArrayElement("salt-nationality-fr", "\"FR\"");
        (string Encoded, string Digest) unitedKingdom = EncodeArrayElement("salt-nationality-uk", "\"UK\"");

        //A digest no disclosure in this credential hashes to: RFC 9901 Section 4.2.5's decoy,
        //which occupies its position in the array and reveals nothing.
        string decoyDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            "decoy", WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = /*lang=json,strict*/ $$"""
        {
            "_sd_alg": "sha-256",
            "iss": "{{Issuer}}",
            "vct": "{{Vct}}",
            "aka_vcts": ["{{DeterministicIdentityAdditionalVct}}"],
            "nationalities": [
                {"...": "{{germany.Digest}}"},
                {"...": "{{france.Digest}}"},
                {"...": "{{unitedKingdom.Digest}}"},
                {"...": "{{decoyDigest}}"}
            ],
            "evidence": [
                {"type": "document"},
                "self_attested"
            ],
            "_sd": [
                "{{familyName.Digest}}",
                "{{employer.Digest}}",
                "{{address.Digest}}",
                "{{ageEqualOrOver.Digest}}",
                "{{ageInYears.Digest}}"
            ]
        }
        """;

        string[] disclosures =
        [
            familyName.Encoded,
            employer.Encoded,
            employerFamilyName.Encoded,
            address.Encoded,
            streetAddress.Encoded,
            locality.Encoded,
            country.Encoded,
            ageEqualOrOver.Encoded,
            ageOver18.Encoded,
            ageOver65.Encoded,
            ageInYears.Encoded,
            germany.Encoded,
            france.Encoded,
            unitedKingdom.Encoded
        ];

        return $"{CreateMinimalJwt(payloadJson)}~{string.Join('~', disclosures)}~";
    }


    /// <summary>
    /// Hand-builds an SD-CWT whose claims map carries always-disclosed <c>iss</c> and <c>vct</c>
    /// under their CWT claim keys, an <c>employer</c> map whose redacted-claim-keys entry carries
    /// the nested <c>family_name</c> disclosure, and a <c>nationalities</c> array of
    /// redacted-element markers — three resolving to disclosures and one a decoy. The signature is
    /// a placeholder — this credential is only ever walked structurally, never cryptographically
    /// verified.
    /// </summary>
    /// <returns>The COSE_Sign1 wire bytes.</returns>
    public static byte[] MintDeterministicSdCwtCredential()
    {
        using SdDisclosure employerFamilyName = SdDisclosure.CreateProperty(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes("salt-cwt-employer-family-name")), "family_name", EmployerFamilyName);
        using SdDisclosure germany = SdDisclosure.CreateArrayElement(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes("salt-cwt-nationality-de")), "DE");
        using SdDisclosure france = SdDisclosure.CreateArrayElement(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes("salt-cwt-nationality-fr")), "FR");
        using SdDisclosure unitedKingdom = SdDisclosure.CreateArrayElement(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes("salt-cwt-nationality-uk")), "UK");

        byte[] decoyDigest = SdCwtSerializer.ComputeDisclosureDigest(
            Encoding.UTF8.GetBytes("decoy"), WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteStartMap(4);

        writer.WriteInt32(WellKnownCwtClaimNames.Iss);
        writer.WriteTextString(Issuer);

        writer.WriteInt32(WellKnownCwtClaimNames.Vct);
        writer.WriteTextString(Vct);

        writer.WriteTextString("employer");
        writer.WriteStartMap(1);
        writer.WriteSimpleValue(SdCwtConstants.RedactedClaimKeysSimpleValue);
        writer.WriteStartArray(1);
        writer.WriteByteString(DigestOf(employerFamilyName));
        writer.WriteEndArray();
        writer.WriteEndMap();

        writer.WriteTextString("nationalities");
        writer.WriteStartArray(4);
        byte[][] elementDigests = [DigestOf(germany), DigestOf(france), DigestOf(unitedKingdom), decoyDigest];
        foreach(byte[] digest in elementDigests)
        {
            writer.WriteTag(new CborTag(SdCwtConstants.RedactedClaimElementTag));
            writer.WriteByteString(digest);
        }

        writer.WriteEndArray();

        writer.WriteEndMap();

        var headerBuffer = new ArrayBufferWriter<byte>();
        var headerWriter = new CborWriter(headerBuffer, CborOptions.RfcCanonical);
        headerWriter.WriteStartMap(1);
        headerWriter.WriteInt32(CoseHeaderParameters.Alg);
        headerWriter.WriteInt32(WellKnownCoseAlgorithms.Es256);
        headerWriter.WriteEndMap();

        var message = new SdCwtMessage(
            buffer.WrittenSpan.ToArray(),
            headerBuffer.WrittenSpan.ToArray(),
            new byte[64],
            [employerFamilyName, germany, france, unitedKingdom]);

        return SdCwtSerializer.Serialize(message);
    }


    /// <summary>
    /// Issues an SD-JWT VC whose issuer-signed payload carries <c>family_name</c> at the top level
    /// and a second <c>family_name</c> inside a plain (non-recursive) <c>employer</c> object,
    /// both selectively disclosable, alongside the always-disclosed <c>iss</c>, <c>vct</c> and
    /// <c>aka_vcts</c>, and bound to <paramref name="holderPublicKey"/> via <c>cnf</c>. Passing
    /// <see langword="null"/> for <paramref name="credentialType"/> issues the same shape with no
    /// <c>vct</c> and no <c>aka_vcts</c>, the credential SD-JWT VC Section 2.2.2.3 refuses.
    /// </summary>
    /// <param name="holderPublicKey">The holder key bound into <c>cnf</c>.</param>
    /// <param name="credentialType">The <c>vct</c> to issue under, or <see langword="null"/> for none.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The serialized SD-JWT (no key binding) and the issuer public key the caller owns.</returns>
    public static async ValueTask<(string SerializedSdJwt, PublicKeyMemory IssuerPublicKey)> MintHolderBoundCredentialAsync(
        PublicKeyMemory holderPublicKey,
        string? credentialType,
        CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        var employer = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["family_name"] = HolderBoundEmployerFamilyName,
            ["name"] = EmployerName
        };

        var claims = new List<KeyValuePair<string, object>>
        {
            new("family_name", SubjectFamilyName),
            new("employer", employer)
        };

        if(credentialType is not null)
        {
            claims.Add(new KeyValuePair<string, object>(
                WellKnownJwtClaimNames.AkaVcts, new[] { HolderBoundAdditionalVct }));
        }

        JwtPayload payload = credentialType is null
            ? JwtPayload.ForIssuance(
                issuer: Issuer,
                issuedAt: TestClock.CanonicalEpoch,
                holderConfirmation: holderJwk,
                claims: claims)
            : JwtPayload.ForSdJwtVcIssuance(
                issuer: Issuer,
                verifiableCredentialType: credentialType,
                issuedAt: TestClock.CanonicalEpoch,
                holderConfirmation: holderJwk,
                claims: claims);

        HashSet<CredentialPath> disclosablePaths =
        [
            CredentialPath.FromJsonPointer(TopLevelFamilyNamePointer),
            CredentialPath.FromJsonPointer(NestedFamilyNamePointer)
        ];

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths,
            TestSalts.DefaultGenerator(),
            issuerPrivateKey,
            IssuerKeyId,
            BaseMemoryPool.Shared,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());

        return (SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder), issuerKeys.PublicKey);
    }


    /// <summary>
    /// Issues an SD-CWT whose claims map carries label 101 at the top level and a second label 101
    /// inside the <c>employer</c> map at label 500, both selectively disclosable, bound to
    /// <paramref name="holderPublicKey"/> via <c>cnf</c>, then rebuilds the full wire form and
    /// parses it back so the token carries the positions its digests resolve to.
    /// </summary>
    /// <param name="issuerPrivateKey">The issuer's signing key.</param>
    /// <param name="holderPublicKey">The holder key carried in <c>cnf</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed stored credential. The caller owns and disposes it.</returns>
    public static async ValueTask<SdToken<ReadOnlyMemory<byte>>> MintHolderBoundSdCwtCredentialAsync(
        PrivateKeyMemory issuerPrivateKey,
        PublicKeyMemory holderPublicKey,
        CancellationToken cancellationToken)
    {
        var employer = new Dictionary<int, object>
        {
            [CwtClaimKeyFamilyName] = HolderBoundEmployerFamilyName,
            [CwtClaimKeyEmployerName] = EmployerName
        };

        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = Issuer,
            [WellKnownCwtClaimNames.Iat] = TestClock.CanonicalEpoch.ToUnixTimeSeconds(),
            [WellKnownCwtClaimNames.Vct] = Vct,
            [WellKnownCwtClaimNames.Cnf] = SdCwtWireFixtures.BuildCnfWithHolderKey(holderPublicKey, CnfCoseKeyMember),
            [CwtClaimKeyFamilyName] = SubjectFamilyName,
            [CwtClaimKeyEmployer] = employer
        };

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(CwtTopLevelFamilyNamePointer),
            CredentialPath.FromJsonPointer(CwtNestedFamilyNamePointer)
        };

        SdToken<ReadOnlyMemory<byte>> issued = await claims.IssueSdCwtTokenAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap,
            SdCwtIssuance.IssueVerboseAsync,
            disclosablePaths,
            TestSalts.DefaultGenerator(),
            issuerPrivateKey,
            IssuerKeyId,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //Issuance hands back a token with no walked payload, so its disclosures carry no positions.
        //Rebuilding the full wire form and parsing it back is what a wallet does when it stores an
        //issued credential, and it is what gives every disclosure the path its digest sits at.
        using(issued)
        {
            SdCwtMessage bare = SdCwtSerializer.Parse(issued.IssuerSigned, TestSalts.TestSaltTag, BaseMemoryPool.Shared);
            var full = new SdCwtMessage(bare.Payload, bare.ProtectedHeader, bare.Signature, issued.Disclosures);
            byte[] wireBytes = SdCwtSerializer.Serialize(full);

            return SdCwtSerializer.ParseToken(wireBytes, TestSalts.TestSaltTag, BaseMemoryPool.Shared, TestSetup.Base64UrlEncoder);
        }
    }


    /// <summary>
    /// Builds the issuer-signed JWT around a payload. The signature is not exercised — these
    /// credentials are only ever walked structurally, which reads the payload regardless of who
    /// signed it.
    /// </summary>
    /// <param name="payloadJson">The issuer-signed payload.</param>
    /// <returns>The compact JWS: header, payload and a placeholder signature, dot-separated.</returns>
    internal static string CreateMinimalJwt(string payloadJson)
    {
        string header = /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""";
        string headerEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header));
        string payloadEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        string signatureEncoded = TestSetup.Base64UrlEncoder(new byte[64]);

        return $"{headerEncoded}.{payloadEncoded}.{signatureEncoded}";
    }


    /// <summary>
    /// Serialises an object-property disclosure and returns both its wire text and the digest the
    /// issuer-signed payload references it by.
    /// </summary>
    /// <param name="saltText">The bytes the disclosure's salt is built from.</param>
    /// <param name="claimName">The disclosure's claim name.</param>
    /// <param name="claimValueJson">The disclosure's claim value, as JSON text.</param>
    /// <returns>The disclosure's wire text and its digest.</returns>
    internal static (string Encoded, string Digest) EncodeProperty(string saltText, string claimName, string claimValueJson)
    {
        using JsonDocument document = JsonDocument.Parse(claimValueJson);
        using SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes(saltText)), claimName, document.RootElement);

        string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);

        return (encoded, SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Serialises an array-element disclosure — the two-element form of RFC 9901 Section 4.2.2,
    /// which carries no claim name — and returns its wire text and digest.
    /// </summary>
    /// <param name="saltText">The bytes the disclosure's salt is built from.</param>
    /// <param name="claimValueJson">The element's value, as JSON text.</param>
    /// <returns>The disclosure's wire text and its digest.</returns>
    private static (string Encoded, string Digest) EncodeArrayElement(string saltText, string claimValueJson)
    {
        using JsonDocument document = JsonDocument.Parse(claimValueJson);
        using SdDisclosure disclosure = SdDisclosure.CreateArrayElement(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes(saltText)), document.RootElement);

        string encoded = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);

        return (encoded, SdJwtPathExtraction.ComputeDisclosureDigest(
            encoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared));
    }


    /// <summary>The digest the issuer-signed CWT payload references an SD-CWT disclosure by.</summary>
    /// <param name="disclosure">The disclosure to digest.</param>
    /// <returns>The digest bytes.</returns>
    private static byte[] DigestOf(SdDisclosure disclosure) =>
        SdCwtSerializer.ComputeDisclosureDigest(
            SdCwtSerializer.SerializeDisclosure(disclosure), WellKnownHashAlgorithms.Sha256Iana, BaseMemoryPool.Shared);
}
