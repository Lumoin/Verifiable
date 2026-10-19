using Lumoin.Veritas.Cbor;
using Microsoft.Extensions.Time.Testing;
using System.Globalization;
using System.Security.Cryptography;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// Firewalled end-to-end tests for the SD-CWT OID4VP key-binding presentation flow:
/// issuer issues an SD-CWT carrying the holder's COSE_Key in its <c>cnf</c> claim →
/// wallet selects disclosures and signs an SD-CWT Key Binding Token (KBT) with its
/// private key → verifier receives ONLY the KBT wire bytes (plus the issuer public
/// key via a resolver) and runs <see cref="KbCwtVerification.VerifyAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// The three parties are firewalled — no shared in-memory disclosures, salts, or keys
/// cross the issuer → wallet → verifier boundary. The verifier reconstructs everything
/// it needs from the KBT bytes: the embedded SD-CWT (from <c>kcwt</c>), the holder
/// public key (from the embedded SD-CWT <c>cnf</c> COSE_Key), and the disclosed claims.
/// Every test uses real key material and real cryptography. The CBOR parse/extraction
/// seams are wired to the real <c>Verifiable.Cbor</c> implementations; the holder and
/// credential signature checks flow through real COSE verification.
/// </para>
/// <para>
/// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see> and
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP 1.0 §8.1</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdCwtKeyBindingFlowTests
{
    public required TestContext TestContext { get; set; }

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";
    private const string VerifierAud = "https://verifier.example.com/response";
    private const string Cnonce = "n-flow";

    //Application-defined CWT claim keys for a test credential.
    private const int ClaimKeyGivenName = 100;
    private const int ClaimKeyFamilyName = 101;
    private const int ClaimKeyEmail = 103;

    //RFC 8747 §3.1: the cnf confirmation map carries the embedded COSE_Key under member 1.
    private const int CnfCoseKeyMember = 1;

    private const string GivenNamePath = "/100";
    private const string FamilyNamePath = "/101";
    private const string EmailPath = "/103";


    [TestMethod]
    public async Task VerifierAcceptsKbtAndExtractsSelectedDisclosures()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //Wallet produces the KBT wire bytes; from here only the bytes + issuer key are used.
        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        SdCwtKbtVerificationResult result = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic).ConfigureAwait(false);

        Assert.IsTrue(result.HolderSignatureValid, "The KBT holder signature must verify.");
        Assert.IsTrue(result.CredentialSignatureValid,
            "The embedded SD-CWT must verify (issuer signature + per-disclosure digest binding).");
        Assert.AreEqual(VerifierAud, result.Audience);
        Assert.AreEqual(Cnonce, result.Cnonce);
        Assert.AreEqual(TimeProvider.GetUtcNow().ToUnixTimeSeconds(), result.IssuedAt?.ToUnixTimeSeconds());

        //Path-keyed per RFC 9901 §9.3 (a claim name is not a stable identity across depths):
        //embeddedToken.DisclosurePaths resolved each disclosure's real position, not its leaf name.
        IReadOnlyDictionary<CredentialPath, object?> claims = result.DisclosedClaims;
        Assert.AreEqual("Erika", claims[CredentialPath.FromJsonPointer(GivenNamePath)]);
        Assert.AreEqual("Mustermann", claims[CredentialPath.FromJsonPointer(FamilyNamePath)]);
        Assert.IsFalse(claims.ContainsKey(CredentialPath.FromJsonPointer(EmailPath)),
            "The withheld email claim must not appear in the disclosed set.");

        //The verifier observes the shortest disclosure salt length for the salt-length signal.
        //Issuance used TestSalts.DefaultGenerator (the recommended 16-byte length).
        Assert.AreEqual(Salt.RecommendedByteLength, result.MinimumDisclosureSaltLengthBytes,
            "The shortest disclosure salt length must be captured from the embedded SD-CWT disclosures.");
    }


    [TestMethod]
    public async Task SameKbtVerifiedTwiceUnderSaltReuseStoreFlagsTheSecond()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        var store = new InMemoryCommitmentStore();
        CommitmentReuseDetectionSeam seam = new(
            SHA256.HashData, HashOutputByteLength: 32, Sha256CommitmentTag, store.IsSeen, store.Record);

        //First verification records the embedded disclosures' salts.
        SdCwtKbtVerificationResult first = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic, seam).ConfigureAwait(false);
        Assert.IsFalse(first.SaltReused, "First verification sees fresh salts.");

        //Re-verifying the SAME KBT replays the same disclosure salts (the embedded SD-CWT is fixed).
        SdCwtKbtVerificationResult second = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic, seam).ConfigureAwait(false);
        Assert.IsTrue(second.SaltReused, "Re-verifying the same KBT must detect the reused disclosure salts.");
    }


    private static Tag Sha256CommitmentTag { get; } = Tag.Create(HashAlgorithmName.SHA256);


    /// <summary>A verifier-side commitment store keyed by commitment bytes, shared across two verifications.</summary>
    private sealed class InMemoryCommitmentStore
    {
        private HashSet<string> Seen { get; } = new(StringComparer.Ordinal);

        public ValueTask<bool> IsSeen(DigestValue commitment, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Seen.Contains(Convert.ToHexString(commitment.AsReadOnlySpan())));

        public ValueTask Record(DigestValue commitment, CancellationToken cancellationToken)
        {
            _ = Seen.Add(Convert.ToHexString(commitment.AsReadOnlySpan()));

            return ValueTask.CompletedTask;
        }
    }


    [TestMethod]
    public async Task CredentialSignatureFailsWhenResolverReturnsWrongIssuerKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        //A different key than the one that signed the credential.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongIssuerPublic = wrongKeys.PublicKey;
        using PrivateKeyMemory wrongIssuerPrivate = wrongKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        //Resolver hands back a key that did NOT sign the credential.
        SdCwtKbtVerificationResult result = await VerifyAsync(kbt.AsReadOnlyMemory(), wrongIssuerPublic).ConfigureAwait(false);

        Assert.IsTrue(result.HolderSignatureValid,
            "The holder signature is independent of the issuer key and must still verify.");
        Assert.IsFalse(result.CredentialSignatureValid,
            "Verifying the credential under the wrong issuer key must fail.");
    }


    [TestMethod]
    public async Task HolderSignatureFailsWhenSignedByKeyNotInCnf()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        //The cnf carries this holder key...
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> cnfKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory cnfHolderPublic = cnfKeys.PublicKey;
        using PrivateKeyMemory cnfHolderPrivate = cnfKeys.PrivateKey;

        //...but the KBT is signed by a different (attacker) key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, cnfHolderPublic, attackerPrivate, Cnonce, TimeProvider.GetUtcNow()).ConfigureAwait(false);

        SdCwtKbtVerificationResult result = await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic).ConfigureAwait(false);

        Assert.IsFalse(result.HolderSignatureValid,
            "The KBT signed by a key that does not match the cnf COSE_Key must fail holder verification.");
        Assert.IsTrue(result.CredentialSignatureValid,
            "The credential itself is intact, so the issuer signature + digest binding still hold.");
    }


    /// <summary>
    /// A Key Binding Token whose genuinely signed protected header carries the <c>kcwt</c> (13) label twice is
    /// refused as malformed by the COSE parser of the Key Binding Token itself, with that parser's own failure,
    /// before any embedded SD-CWT is parsed.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// </summary>
    [TestMethod]
    public async Task VerifierRefusesAKbtRepeatingKcwt()
    {
        await AssertKbtRefusedAsync<CborContentException>(
            SdCwtVpFixture.BuildProtectedHeaderWithKcwtTwice, SdKbtIssuance.BuildPayload).ConfigureAwait(false);
    }


    /// <summary>
    /// A Key Binding Token whose embedded SD-CWT carries <c>sd_claims</c> twice in its unprotected bucket, every
    /// Disclosure still present, is refused as malformed with the embedded SD-CWT parse's own failure.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// </summary>
    [TestMethod]
    public async Task VerifierRefusesAKbtWhoseSdCwtRepeatsSdClaims()
    {
        await AssertKbtRefusedAsync<FormatException>(
            SdCwtVpFixture.BuildProtectedHeaderWithSdClaimsTwice, SdKbtIssuance.BuildPayload).ConfigureAwait(false);
    }


    /// <summary>
    /// A Key Binding Token whose genuinely signed claims map carries the <c>aud</c> (3) claim twice is refused as
    /// malformed with the claims reader's own failure.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of the
    /// listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input." Its
    /// step 7: "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that has
    /// duplicate keys may be well-formed, but it is not valid".
    /// </summary>
    [TestMethod]
    public async Task VerifierRefusesAKbtRepeatingAClaim()
    {
        await AssertKbtRefusedAsync<FormatException>(
            SdKbtIssuance.BuildProtectedHeader, SdCwtVpFixture.BuildPayloadWithAudTwice).ConfigureAwait(false);
    }


    /// <summary>
    /// An SD-CWT carrying no <c>sd_claims</c>, whose genuinely issuer-signed protected bucket carries <c>alg</c> twice
    /// while its unprotected bucket is empty, is refused by the issuer-signature verification with the COSE parser's
    /// own failure. <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in
    /// each of the maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST
    /// be rejected as malformed."
    /// </summary>
    [TestMethod]
    public async Task IssuerSignatureVerificationRefusesAnSdCwtRepeatingAProtectedLabel()
    {
        await AssertIssuerSignatureVerificationRefusesAsync([0xA2, 0x01, 0x26, 0x01, 0x26]).ConfigureAwait(false);
    }


    /// <summary>
    /// An SD-CWT carrying no <c>sd_claims</c>, whose genuinely issuer-signed protected bucket carries <c>alg</c> twice
    /// and then a byte-string label, an entry that cannot be read, is refused by the issuer-signature verification with
    /// the COSE parser's own failure: each label is judged as it is read. The verification calls the issuer-signature
    /// parse directly.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "Labels in each of the
    /// maps MUST be unique. When processing messages, if a label appears multiple times, the message MUST be rejected
    /// as malformed."
    /// </summary>
    /// <param name="protectedHeader">The serialized protected bucket the issuer signature covers.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA3, 0x01, 0x26, 0x01, 0x26, 0x41, 0x00, 0x00 }, DisplayName = "alg twice, then a byte-string label")]
    public async Task IssuerSignatureVerificationRefusesARepeatBeforeAnUnreadableProtectedEntry(byte[] protectedHeader)
    {
        await AssertIssuerSignatureVerificationRefusesAsync(protectedHeader).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs an SD-CWT carrying no <c>sd_claims</c> under a fresh issuer key over <paramref name="protectedHeader"/> as
    /// given, its unprotected bucket empty, and asserts the issuer-signature verification refuses it with the COSE
    /// parser's own failure.
    /// </summary>
    /// <param name="protectedHeader">The serialized protected bucket the issuer signature covers.</param>
    /// <returns>A task that completes when the refusal has been asserted.</returns>
    private async Task AssertIssuerSignatureVerificationRefusesAsync(byte[] protectedHeader)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        byte[] repeatedAlgorithmHeader = protectedHeader;
        byte[] payload = SdCwtWireFixtures.SerializeCwtClaimMap(new Dictionary<int, object> { [WellKnownCwtClaimNames.Iss] = IssuerId }).ToArray();

        using CoseSign1Message signed = await Verifiable.JCose.Cose.SignAsync(
            EncodedCoseProtectedHeader.FromBytes(repeatedAlgorithmHeader, Pool),
            null,
            payload,
            CoseSerialization.BuildSigStructure,
            issuerPrivate,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] sdCwt = CoseWireFixtures.ComposeCoseSign1(repeatedAlgorithmHeader, [0xA0], payload, signed.Signature.AsReadOnlySpan());
        using SdToken<ReadOnlyMemory<byte>> token = new(sdCwt, []);

        _ = await Assert.ThrowsExactlyAsync<CborContentException>(
            async () => await token.VerifyIssuerSignatureAsync(
                issuerPublic, Pool, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false),
            "RFC 9052 Section 3: an SD-CWT whose protected bucket repeats a label is rejected as malformed.").ConfigureAwait(false);
    }


    /// <summary>
    /// Issues an SD-CWT, signs a genuine Key Binding Token over it with the supplied header and payload builders,
    /// and asserts the verifier refuses the token with <typeparamref name="TException"/>.
    /// </summary>
    /// <typeparam name="TException">The refusing reader's own failure type.</typeparam>
    /// <param name="buildProtectedHeader">Builds the Key Binding Token's protected header.</param>
    /// <param name="buildPayload">Builds the Key Binding Token's payload.</param>
    /// <returns>A task that completes when the refusal has been asserted.</returns>
    private async Task AssertKbtRefusedAsync<TException>(
        BuildKbtProtectedHeaderDelegate buildProtectedHeader, BuildKbtPayloadDelegate buildPayload)
        where TException : Exception
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The library's serializer refuses to write a protected bucket repeating a label, so the wire form is assembled as given.
        using EncodedCoseSign1 kbt = await IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, Cnonce, TimeProvider.GetUtcNow(),
            buildProtectedHeader, buildPayload, CoseWireFixtures.SerializeCoseSign1AsGiven).ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<TException>(
            async () => await VerifyAsync(kbt.AsReadOnlyMemory(), issuerPublic).ConfigureAwait(false),
            "A Key Binding Token repeating a label in one map is malformed and is never verified.").ConfigureAwait(false);
    }


    /// <summary>
    /// The issuer issues an SD-CWT (the holder's COSE_Key in <c>cnf</c> and selectively disclosable claims), then the
    /// wallet selects given_name and family_name and signs the Key Binding Token with the holder's private key, its
    /// header, payload and wire form written by the library's own builders and serializer.
    /// </summary>
    /// <param name="issuerPrivate">The issuer's signing key.</param>
    /// <param name="holderPublic">The holder's public key, embedded in the <c>cnf</c> claim.</param>
    /// <param name="holderPrivate">The holder's private key the Key Binding Token is signed with.</param>
    /// <param name="cnonce">The verifier nonce bound into the Key Binding Token.</param>
    /// <param name="iat">The instant the Key Binding Token is issued at.</param>
    /// <returns>The Key Binding Token wire bytes.</returns>
    private ValueTask<EncodedCoseSign1> IssueKbtAsync(
        PrivateKeyMemory issuerPrivate,
        PublicKeyMemory holderPublic,
        PrivateKeyMemory holderPrivate,
        string cnonce,
        DateTimeOffset iat) =>
        IssueKbtAsync(
            issuerPrivate, holderPublic, holderPrivate, cnonce, iat,
            SdKbtIssuance.BuildProtectedHeader, SdKbtIssuance.BuildPayload, CoseSerialization.SerializeCoseSign1);


    /// <summary>
    /// Issues an SD-CWT and signs the Key Binding Token over the given_name and family_name Disclosures with the
    /// supplied header and payload builders, its wire form written by the supplied serializer.
    /// </summary>
    /// <param name="issuerPrivate">The issuer's signing key.</param>
    /// <param name="holderPublic">The holder's public key, embedded in the <c>cnf</c> claim.</param>
    /// <param name="holderPrivate">The holder's private key the Key Binding Token is signed with.</param>
    /// <param name="cnonce">The verifier nonce bound into the Key Binding Token.</param>
    /// <param name="iat">The instant the Key Binding Token is issued at.</param>
    /// <param name="buildProtectedHeader">Builds the Key Binding Token's protected header.</param>
    /// <param name="buildPayload">Builds the Key Binding Token's payload.</param>
    /// <param name="serializeCoseSign1">Writes the signed Key Binding Token's wire form.</param>
    /// <returns>The Key Binding Token wire bytes.</returns>
    private async ValueTask<EncodedCoseSign1> IssueKbtAsync(
        PrivateKeyMemory issuerPrivate,
        PublicKeyMemory holderPublic,
        PrivateKeyMemory holderPrivate,
        string cnonce,
        DateTimeOffset iat,
        BuildKbtProtectedHeaderDelegate buildProtectedHeader,
        BuildKbtPayloadDelegate buildPayload,
        SerializeCoseSign1Delegate serializeCoseSign1)
    {
        using SdToken<ReadOnlyMemory<byte>> issuedToken = await IssueSdCwtTokenAsync(
            issuerPrivate, holderPublic, TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<ReadOnlyMemory<byte>> presentationToken = SelectGivenAndFamily(issuedToken);

        return await KbCwtIssuance.IssueAsync(
            presentationToken,
            holderPrivate,
            verifierAud: VerifierAud,
            verifierCnonce: cnonce,
            iat: iat,
            buildProtectedHeader: buildProtectedHeader,
            buildPayload: buildPayload,
            buildSigStructure: CoseSerialization.BuildSigStructure,
            serializeCoseSign1: serializeCoseSign1,
            memoryPool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //The verifier side — wired entirely to the real Verifiable.Cbor seams and a resolver
    //returning the supplied issuer public key. It receives ONLY the KBT wire bytes and
    //the issuer public key; everything else is reconstructed from the bytes.
    private async ValueTask<SdCwtKbtVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> kbtBytes, PublicKeyMemory issuerKey, CommitmentReuseDetectionSeam? saltReuseSeam = null)
    {
        return await KbCwtVerification.VerifyAsync(
            kbtBytes,
            parseCoseSign1: CoseSerialization.ParseCoseSign1,
            extractKcwt: SdCwtVpParsing.ExtractKcwt,
            parseSdCwt: bytes => SdCwtVpParsing.ParseEmbeddedSdCwt(bytes, TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder),
            extractHolderKey: SdCwtVpParsing.ExtractHolderKey,
            readKbtClaims: SdCwtVpParsing.ReadKbtClaims,
            extractIssuer: SdCwtVpParsing.ExtractIssuer,
            extractCredentialType: SdCwtVpParsing.ExtractCredentialType,
            extractStatus: SdCwtVpParsing.ExtractStatus,
            resolveIssuerKey: _ => issuerKey,
            verifyCredential: async (token, key, pool, ct) =>
            {
                SdVerificationResult result = await token.VerifyAsync(
                    key, pool,
                    CoseSerialization.ParseCoseSign1, SdCwtPathExtraction.ExtractPaths, CoseSerialization.BuildSigStructure, TestSetup.Base64UrlEncoder,
                    cancellationToken: ct).ConfigureAwait(false);

                return result.IsValid;
            },
            buildSigStructure: CoseSerialization.BuildSigStructure,
            saltReuseSeam: saltReuseSeam,
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Issues a signed SD-CWT carrying the holder COSE_Key under cnf (claim 8) plus
    //given_name, family_name, and email as selectively disclosable claims.
    private async ValueTask<SdToken<ReadOnlyMemory<byte>>> IssueSdCwtTokenAsync(
        PrivateKeyMemory privateKey, PublicKeyMemory holderPublic, CancellationToken cancellationToken)
    {
        var claims = new Dictionary<int, object>
        {
            [WellKnownCwtClaimNames.Iss] = IssuerId,
            [WellKnownCwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            [WellKnownCwtClaimNames.Cnf] = SdCwtWireFixtures.BuildCnfWithHolderKey(holderPublic, CnfCoseKeyMember),
            [ClaimKeyGivenName] = "Erika",
            [ClaimKeyFamilyName] = "Mustermann",
            [ClaimKeyEmail] = "erika@example.de"
        };

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer(GivenNamePath),
            CredentialPath.FromJsonPointer(FamilyNamePath),
            CredentialPath.FromJsonPointer(EmailPath)
        };

        return await claims.IssueSdCwtTokenAsync(
            SdCwtWireFixtures.SerializeCwtClaimMap, SdCwtIssuance.IssueVerboseAsync, disclosablePaths,
            TestSalts.DefaultGenerator(),
            privateKey, IssuerKeyId, Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    //Selects given_name + family_name, leaving email behind.
    private static SdToken<ReadOnlyMemory<byte>> SelectGivenAndFamily(SdToken<ReadOnlyMemory<byte>> issuedToken)
    {
        HashSet<string> selected = new(StringComparer.Ordinal)
        {
            ClaimKeyGivenName.ToString(CultureInfo.InvariantCulture),
            ClaimKeyFamilyName.ToString(CultureInfo.InvariantCulture)
        };

        return issuedToken.SelectDisclosures(
            d => d.ClaimName is not null && selected.Contains(d.ClaimName), Pool);
    }
}
