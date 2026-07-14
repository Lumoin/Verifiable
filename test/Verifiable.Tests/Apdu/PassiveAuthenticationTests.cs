using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.BouncyCastle;
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
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
                MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
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
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AllDataGroupsValid,
            "A passport whose data groups (DataGroup1/2.Write) and EF.SOD (DocumentSecurityObject.Write) are minted by our writers must pass Passive Authentication.");
    }


    [TestMethod]
    public async Task RejectsASha1SecurityObjectByDefault()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.MintWithSha1SecurityObject();

        //SHA-1 is collision-forgeable, so the default policy rejects a SHA-1 LDS Security Object.
        bool threw = false;
        try
        {
            _ = await PassiveAuthentication.VerifyAsync(
                passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
                MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "A SHA-1 LDS Security Object MUST be rejected under the default policy.");
    }


    [TestMethod]
    public async Task AcceptsASha1SecurityObjectWhenThePolicyAllowsIt()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.MintWithSha1SecurityObject();

        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared,
            new PassiveAuthenticationPolicy { AllowSha1SecurityObject = true }, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HashAlgorithmName.SHA1, result.HashAlgorithm, "The SHA-1 security object's algorithm is reported.");
        Assert.IsTrue(result.AllDataGroupsValid, "With SHA-1 allowed, every SHA-1 data-group hash must still match.");
    }


    [TestMethod]
    public async Task RejectsANonConformantDocumentSignerCertificateByDefault()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.MintWithNonConformantDocumentSigner();

        //A Document Signer marked as a CA (and asserting keyCertSign) violates the ICAO Doc 9303 Part 12 Document
        //Signer profile — it could issue further certificates — so the default policy rejects it.
        bool threw = false;
        try
        {
            _ = await PassiveAuthentication.VerifyAsync(
                passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
                MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "A non-conformant Document Signer certificate MUST be rejected under the default policy.");
    }


    [TestMethod]
    public async Task AcceptsANonConformantDocumentSignerWhenThePolicyAllowsIt()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.MintWithNonConformantDocumentSigner();

        //With the profile gate opted out, the same passport verifies — proving the default rejection is the
        //profile gate alone and the certificate otherwise chains to the trusted CSCA.
        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared,
            new PassiveAuthenticationPolicy { AllowNonConformantDocumentSignerCertificate = true }, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AllDataGroupsValid,
            "With the Document Signer profile gate opted out, a non-conformant but correctly chained signer verifies.");
    }


    [TestMethod]
    public void ReadsDocumentSignerAndCscaProfilesConsistentlyAcrossBackends()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        //The Document Signer is a signer, not a CA: digitalSignature only. The CSCA is a CA: keyCertSign + cA=TRUE
        //and no digitalSignature. Both backends must read the same neutral profile — proving the seam is provider-neutral.
        X509CertificateProfile documentSignerMicrosoft = MicrosoftX509Functions.ReadCertificateProfile(passport.DocumentSignerCertificate);
        X509CertificateProfile documentSignerBouncyCastle = BouncyCastleX509Functions.ReadCertificateProfile(passport.DocumentSignerCertificate);
        X509CertificateProfile cscaMicrosoft = MicrosoftX509Functions.ReadCertificateProfile(passport.CscaAnchor);
        X509CertificateProfile cscaBouncyCastle = BouncyCastleX509Functions.ReadCertificateProfile(passport.CscaAnchor);

        Assert.AreEqual(documentSignerMicrosoft, documentSignerBouncyCastle, "Both backends must read the same Document Signer profile.");
        Assert.AreEqual(cscaMicrosoft, cscaBouncyCastle, "Both backends must read the same CSCA profile.");

        Assert.IsTrue(documentSignerMicrosoft.AssertsDigitalSignature, "The Document Signer asserts digitalSignature.");
        Assert.IsFalse(documentSignerMicrosoft.AssertsKeyCertSign, "The Document Signer does not assert keyCertSign.");
        Assert.IsFalse(documentSignerMicrosoft.IsCertificateAuthority, "The Document Signer is not a certificate authority.");

        Assert.IsFalse(cscaMicrosoft.AssertsDigitalSignature, "The CSCA does not assert digitalSignature.");
        Assert.IsTrue(cscaMicrosoft.AssertsKeyCertSign, "The CSCA asserts keyCertSign.");
        Assert.IsTrue(cscaMicrosoft.IsCertificateAuthority, "The CSCA is a certificate authority.");
    }


    [TestMethod]
    public void BothBackendsRejectADocumentSignerCertificateWithDuplicateExtensions()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        //Turn the conformant Document Signer into one carrying two KeyUsage extensions (the second asserting
        //keyCertSign), which RFC 5280 §4.2 forbids. Reading only the first, conformant instance would defeat the
        //Document Signer profile gate, so neither backend may derive a profile from an arbitrarily chosen instance —
        //both must fail closed on the same bytes.
        using PkiCertificateMemory duplicateExtensionCertificate =
            SyntheticPassportFactory.WithDuplicateKeyUsageExtension(passport.DocumentSignerCertificate);

        bool microsoftThrew = false;
        try
        {
            _ = MicrosoftX509Functions.ReadCertificateProfile(duplicateExtensionCertificate);
        }
        catch(CryptographicException)
        {
            microsoftThrew = true;
        }

        bool bouncyCastleThrew = false;
        try
        {
            _ = BouncyCastleX509Functions.ReadCertificateProfile(duplicateExtensionCertificate);
        }
        catch(CryptographicException)
        {
            bouncyCastleThrew = true;
        }

        Assert.IsTrue(microsoftThrew, "The Microsoft reader must reject a certificate with duplicate extensions.");
        Assert.IsTrue(bouncyCastleThrew, "The BouncyCastle reader must reject a certificate with duplicate extensions (as the same CryptographicException the Microsoft backend throws).");
    }


    [TestMethod]
    public async Task PassiveAuthenticationRejectsARevokedDocumentSigner()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        //Passive Authentication forwards the supplied checker to chain validation; a revoked signer is rejected fail-closed.
        string? rejectionMessage = null;
        try
        {
            _ = await PassiveAuthentication.VerifyAsync(
                passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
                MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared,
                checkRevocation: ReportsRevoked, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException exception)
        {
            rejectionMessage = exception.Message;
        }

        Assert.IsNotNull(rejectionMessage, "A revoked Document Signer MUST be rejected.");
        Assert.Contains("revocation", rejectionMessage, "The rejection must originate from the revocation check.");
    }


    [TestMethod]
    public async Task PassiveAuthenticationRejectsAnIndeterminateRevocationStatus()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        //An Unknown status (responder unreachable, no CRL) fails closed: the signer's standing cannot be confirmed.
        string? rejectionMessage = null;
        try
        {
            _ = await PassiveAuthentication.VerifyAsync(
                passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
                MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared,
                checkRevocation: ReportsUnknown, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException exception)
        {
            rejectionMessage = exception.Message;
        }

        Assert.IsNotNull(rejectionMessage, "An indeterminate revocation status MUST be rejected.");
        Assert.Contains("revocation", rejectionMessage, "The rejection must originate from the revocation check.");
    }


    [TestMethod]
    public async Task PassiveAuthenticationAcceptsAGoodDocumentSigner()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();

        PassiveAuthenticationResult result = await PassiveAuthentication.VerifyAsync(
            passport.EfSod, passport.DataGroups, [passport.CscaAnchor], ValidationTime,
            MicrosoftX509Functions.ValidateChainAsync, BaseMemoryPool.Shared,
            checkRevocation: ReportsGood, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AllDataGroupsValid, "An affirmative Good revocation status must let Passive Authentication succeed.");
    }


    [TestMethod]
    public async Task ChainValidationRejectsARevokedLeafOnBothBackends()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();
        PkiCertificateMemory[] chain = [passport.DocumentSignerCertificate];
        PkiCertificateMemory[] anchors = [passport.CscaAnchor];

        //Revocation now lives in the chain validator itself, so both backends of the shared seam reject a revoked leaf.
        string? microsoftMessage = null;
        try
        {
            using PublicKeyMemory microsoftKey = await MicrosoftX509Functions.ValidateChainAsync(
                chain, anchors, ValidationTime, BaseMemoryPool.Shared, ReportsRevoked, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException exception)
        {
            microsoftMessage = exception.Message;
        }

        string? bouncyCastleMessage = null;
        try
        {
            using PublicKeyMemory bouncyCastleKey = await BouncyCastleX509Functions.ValidateChainAsync(
                chain, anchors, ValidationTime, BaseMemoryPool.Shared, ReportsRevoked, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(SecurityException exception)
        {
            bouncyCastleMessage = exception.Message;
        }

        Assert.IsNotNull(microsoftMessage, "The Microsoft chain validator must reject a revoked leaf.");
        Assert.Contains("revocation", microsoftMessage, "The Microsoft rejection must come from the revocation check.");
        Assert.IsNotNull(bouncyCastleMessage, "The BouncyCastle chain validator must reject a revoked leaf.");
        Assert.Contains("revocation", bouncyCastleMessage, "The BouncyCastle rejection must come from the revocation check.");
    }


    [TestMethod]
    public async Task ChainValidationReturnsTheLeafKeyWhenRevocationReportsGood()
    {
        using SyntheticPassport passport = SyntheticPassportFactory.Mint();
        PkiCertificateMemory[] chain = [passport.DocumentSignerCertificate];
        PkiCertificateMemory[] anchors = [passport.CscaAnchor];

        //A Good revocation status does not block an otherwise-valid chain: the leaf key is returned.
        using PublicKeyMemory leafKey = await MicrosoftX509Functions.ValidateChainAsync(
            chain, anchors, ValidationTime, BaseMemoryPool.Shared, ReportsGood, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(leafKey, "A Good revocation status must let chain validation return the leaf key.");
    }


    /// <summary>A revocation checker that affirmatively reports the Document Signer is not revoked.</summary>
    private static CheckCertificateRevocationStatusAsyncDelegate ReportsGood { get; } =
        (certificate, issuerCandidates, validationTime, pool, cancellationToken) => ValueTask.FromResult(CertificateRevocationStatus.Good);

    /// <summary>A revocation checker that reports the Document Signer has been revoked.</summary>
    private static CheckCertificateRevocationStatusAsyncDelegate ReportsRevoked { get; } =
        (certificate, issuerCandidates, validationTime, pool, cancellationToken) => ValueTask.FromResult(CertificateRevocationStatus.Revoked);

    /// <summary>A revocation checker that reports an indeterminate status (as if the responder were unreachable).</summary>
    private static CheckCertificateRevocationStatusAsyncDelegate ReportsUnknown { get; } =
        (certificate, issuerCandidates, validationTime, pool, cancellationToken) => ValueTask.FromResult(CertificateRevocationStatus.Unknown);


    /// <summary>Produces a copy of an elementary file with its final byte flipped, in pooled memory.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the pooled buffer transfers to the returned ElementaryFile, which the caller disposes.")]
    private static ElementaryFile Tamper(ElementaryFile source)
    {
        IMemoryOwner<byte> owner = SyntheticPassportFactory.ToPooled(source.Content);
        owner.Memory.Span[^1] ^= 0x01;

        return new ElementaryFile(owner, source.FileIdentifier);
    }
}
