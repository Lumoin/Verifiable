using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates ICAO Doc 9303 Part 11 Passive Authentication end to end against a minted synthetic passport: a
/// self-signed Country Signing CA, a Document Signer certificate issued under it, and an EF.SOD whose CMS
/// SignedData over the LDS Security Object is signed by the Document Signer. The data are fabricated by
/// <see cref="SyntheticPassportFactory"/> so the test is fully firewalled; a published sample eMRTD set plugs
/// into the same <see cref="PassiveAuthentication.VerifyAsync"/> path as a future conformance cross-check.
/// </summary>
[TestClass]
internal sealed class PassiveAuthenticationTests
{
    private static readonly DateTimeOffset ValidationTime = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task VerifiesAMintedSyntheticPassport()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HashAlgorithmName.SHA256, result.HashAlgorithm, "The security object uses SHA-256.");
        Assert.IsTrue(result.AllDataGroupsValid, "Every read data group must match its signed hash.");
        Assert.IsTrue(result.DataGroupHashesValid[1], "DG1 must match.");
        Assert.IsTrue(result.DataGroupHashesValid[2], "DG2 must match.");
    }


    [TestMethod]
    public async Task RejectsATamperedDataGroup()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        //Flip a byte of DG1 after the EF.SOD was signed over its original hash.
        using ElementaryFile tamperedDg1 = Tamper(passport.DataGroups[1]);
        var tampered = new Dictionary<int, ElementaryFile>
        {
            [1] = tamperedDg1,
            [2] = passport.DataGroups[2]
        };

        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, tampered, [passport.CscaAnchor], ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.AllDataGroupsValid, "A tampered data group must fail Passive Authentication.");
        Assert.IsFalse(result.DataGroupHashesValid[1], "The tampered DG1 must not match.");
        Assert.IsTrue(result.DataGroupHashesValid[2], "The untouched DG2 must still match.");
    }


    [TestMethod]
    public async Task RejectsADocumentSignerThatDoesNotChainToTheTrustedCsca()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();
        using SyntheticPassport other = SyntheticPassportFactory.Mint();

        //Present the second passport's CSCA as the only trust anchor: the first passport's Document Signer does
        //not chain to it, so the chain step must throw.
        bool threw = false;
        try
        {
            _ = await PassiveAuthentication.VerifyAsync(
                passport.EfSod, passport.DataGroups, [other.CscaAnchor], ValidationTime,
                MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "A Document Signer that does not chain to the trusted CSCA must be rejected.");
    }


    [TestMethod]
    public void EfSodWriterRoundTripsThroughExtractSignedData()
    {
        //CmsSignedData is a content-agnostic carrier, so an arbitrary stand-in proves the 0x77 framing.
        using CmsSignedData original = CmsSignedData.FromBytes(Convert.FromHexString("DEADBEEFCAFEBABE"), BaseMemoryPool.Shared);

        using ElementaryFile efSod = DocumentSecurityObject.Write(original, BaseMemoryPool.Shared);
        Assert.AreEqual((byte)0x77, efSod.AsReadOnlySpan()[0], "EF.SOD begins with the 0x77 application tag.");

        using CmsSignedData extracted = DocumentSecurityObject.ExtractSignedData(efSod, BaseMemoryPool.Shared);
        Assert.AreEqual(Convert.ToHexString(original.AsReadOnlySpan()), Convert.ToHexString(extracted.AsReadOnlySpan()),
            "ExtractSignedData must recover exactly the CMS that Write wrapped.");
    }


    [TestMethod]
    public async Task VerifiesAPassportWhoseDataGroupsAndEfSodAreMintedByOurWriters()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.MintFromWriters();

        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AllDataGroupsValid,
            "A passport whose data groups (DataGroup1/2.Write) and EF.SOD (DocumentSecurityObject.Write) are minted by our writers must pass Passive Authentication.");
    }


    /// <summary>Produces a copy of an elementary file with its final byte flipped, in pooled memory.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled buffer transfers to the returned ElementaryFile, which the caller disposes.")]
    private static ElementaryFile Tamper(ElementaryFile source)
    {
        IMemoryOwner<byte> owner = SyntheticPassportFactory.ToPooled(source.Content);
        owner.Memory.Span[^1] ^= 0x01;

        return new ElementaryFile(owner, source.FileIdentifier);
    }
}
