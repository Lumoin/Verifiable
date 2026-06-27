using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates ICAO CSCA Master List parsing (ICAO Doc 9303 Part 12): a CMS SignedData over a
/// <c>CscaMasterList</c> (a set of Country Signing CA certificates) is verified and its CSCA certificates are
/// extracted as Passive Authentication trust anchors. The master list is minted here with an independent base
/// class library signer (the firewall oracle), so the verifier only ever sees the wire bytes; a published
/// master list plugs into <see cref="CscaMasterList.ParseAsync"/> unchanged. The final test closes the
/// real-world loop: a CSCA recovered from a parsed master list verifies a synthetic passport end to end.
/// </summary>
[TestClass]
internal sealed class CscaMasterListTests
{
    private static readonly DateTimeOffset NotBefore = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ValidationTime = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The id-icao-mrtd-security-ldsSecurityObject content type, a valid CMS content type that is not a master list.</summary>
    private const string LdsSecurityObjectOid = "2.23.136.1.1.1";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task ParsesAMintedMasterListAndExtractsItsCertificates()
    {
        using ECDsa signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa firstKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa secondKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 signer = CmsSignedDataTestFactory.MintSelfSignedCertificate(signerKey, NotBefore, NotAfter);
        using X509Certificate2 first = SyntheticPassportFactory.MintCsca(firstKey);
        using X509Certificate2 second = SyntheticPassportFactory.MintCsca(secondKey);

        using CmsSignedData masterList = CmsSignedDataTestFactory.SignAsCms(
            BuildMasterListContent(first.RawData, second.RawData), CscaMasterList.ContentTypeOid, signer);

        using CscaMasterListContent parsed = await CscaMasterList.ParseAsync(masterList, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, parsed.Version, "The master-list version is 0.");
        Assert.HasCount(2, parsed.CountrySigningCertificateAuthorities, "Both CSCA certificates must be extracted.");
        CollectionAssert.AreEquivalent(
            new[] { Convert.ToHexString(first.RawData), Convert.ToHexString(second.RawData) },
            new[]
            {
                Convert.ToHexString(parsed.CountrySigningCertificateAuthorities[0].AsReadOnlySpan()),
                Convert.ToHexString(parsed.CountrySigningCertificateAuthorities[1].AsReadOnlySpan())
            },
            "Each extracted CSCA certificate must be byte-for-byte the one the master list carried.");
        Assert.AreEqual(Convert.ToHexString(signer.RawData), Convert.ToHexString(parsed.SignerCertificate.AsReadOnlySpan()),
            "The signer certificate must be the Master List Signer the CMS embedded.");
    }


    [TestMethod]
    public async Task RejectsCmsWithTheWrongContentType()
    {
        using ECDsa signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 signer = CmsSignedDataTestFactory.MintSelfSignedCertificate(signerKey, NotBefore, NotAfter);
        using X509Certificate2 csca = SyntheticPassportFactory.MintCsca(cscaKey);

        //A correctly structured CscaMasterList signed under a different (non-master-list) content type.
        using CmsSignedData notAMasterList = CmsSignedDataTestFactory.SignAsCms(
            BuildMasterListContent(csca.RawData), LdsSecurityObjectOid, signer);

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await CscaMasterList.ParseAsync(notAMasterList, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A CMS whose content type is not id-icao-cscaMasterList must be rejected.").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task RejectsATamperedMasterList()
    {
        using ECDsa signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa cscaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 signer = CmsSignedDataTestFactory.MintSelfSignedCertificate(signerKey, NotBefore, NotAfter);
        using X509Certificate2 csca = SyntheticPassportFactory.MintCsca(cscaKey);

        using CmsSignedData masterList = CmsSignedDataTestFactory.SignAsCms(
            BuildMasterListContent(csca.RawData), CscaMasterList.ContentTypeOid, signer);
        //Flip a byte inside the signed CSCA certificate (the CSCA subject common name lies in the signed
        //content, before the unsigned embedded signer certificate), so the CMS signature no longer verifies.
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(masterList, "Verifiable Test CSCA"u8);

        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () => await CscaMasterList.ParseAsync(tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A master list whose signed content has been tampered must fail CMS verification.").ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ACscaRecoveredFromAMasterListVerifiesAPassport()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        using ECDsa signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signer = CmsSignedDataTestFactory.MintSelfSignedCertificate(signerKey, NotBefore, NotAfter);
        using X509Certificate2 otherCsca = SyntheticPassportFactory.MintCsca(otherKey);

        //A master list carrying the passport's own CSCA alongside an unrelated one. The trust anchors Passive
        //Authentication uses come only from the parsed master list — the verifier never sees the in-memory CSCA.
        using CmsSignedData masterList = CmsSignedDataTestFactory.SignAsCms(
            BuildMasterListContent(otherCsca.RawData, passport.CscaAnchor.AsReadOnlyMemory()), CscaMasterList.ContentTypeOid, signer);

        using CscaMasterListContent parsed = await CscaMasterList.ParseAsync(masterList, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, passport.DataGroups, parsed.CountrySigningCertificateAuthorities, ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AllDataGroupsValid,
            "A passport whose Document Signer chains to a CSCA recovered from a parsed master list must pass Passive Authentication.");
    }


    /// <summary>
    /// Builds a <c>CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }</c> over the
    /// given DER certificates (version 0). The DER SET OF is canonically ordered by the writer.
    /// </summary>
    private static byte[] BuildMasterListContent(params ReadOnlyMemory<byte>[] certificates)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(0);
            using(writer.PushSetOf())
            {
                foreach(ReadOnlyMemory<byte> certificate in certificates)
                {
                    writer.WriteEncodedValue(certificate.Span);
                }
            }
        }

        return writer.Encode();
    }
}
