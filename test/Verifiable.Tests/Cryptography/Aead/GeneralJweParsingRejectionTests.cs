using System.Buffers;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Adversarial parser-hardening tests for <see cref="GeneralJweParsing.ParseGeneralJson"/>. Each
/// test feeds a structurally or cryptographically malformed General JSON Serialization and asserts
/// the exact rejection: oversize input and the mode gate are distinguished from the structural
/// FormatExceptions. The known-good baseline is a freshly encrypted single-recipient anoncrypt
/// (ECDH-ES+A256KW / A256GCM, X25519) or, where a P-256 EC <c>epk</c> is needed, a P-256 anoncrypt;
/// the malformed inputs are produced by minimal, exact string edits of that baseline (or, for the
/// algorithm and curve mutations, by decoding the base64url <c>protected</c> header, editing the
/// inner JSON, and re-encoding).
/// </summary>
[TestClass]
internal sealed class GeneralJweParsingRejectionTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly byte[] Plaintext =
        Encoding.UTF8.GetBytes(/*lang=json,strict*/ "{\"type\":\"https://didcomm.org/routing/2.0/forward\"}");

    private const string RecipientKid = "did:example:recipient-0#key-1";


    [TestMethod]
    public void RejectsOversizeInput()
    {
        //GeneralJweParsing.MaxGeneralJweByteCount gate (lines 73-78): a string longer than the
        //maximum is rejected as an ArgumentException before any parsing begins.
        string oversize = new('a', GeneralJweParsing.MaxGeneralJweByteCount + 1);

        Assert.ThrowsExactly<ArgumentException>(() => GeneralJweParsing.ParseGeneralJson(
                oversize,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "Input exceeding MaxGeneralJweByteCount must be rejected with ArgumentException.");
    }


    [TestMethod]
    public async Task RejectsMissingProtected()
    {
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = RemoveTopLevelStringMember(general, "protected");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A General JSON JWE without a 'protected' member must be rejected (RFC 7516 §7.2.1).");
    }


    [TestMethod]
    [DataRow("iv", DisplayName = "Missing iv")]
    [DataRow("ciphertext", DisplayName = "Missing ciphertext")]
    [DataRow("tag", DisplayName = "Missing tag")]
    public async Task RejectsMissingIvCiphertextTag(string member)
    {
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = RemoveTopLevelStringMember(general, member);

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            $"A General JSON JWE missing '{member}' must be rejected (RFC 7516 §7.2.1).");
    }


    [TestMethod]
    public async Task RejectsEmptyRecipientsArray()
    {
        //An empty recipients array parses structurally but yields zero entries, which the
        //"at least one entry" gate (lines 114-118) rejects.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = ReplaceRecipientsArray(general, "[]");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A General JSON JWE with an empty 'recipients' array must be rejected (RFC 7516 §7.2.1).");
    }


    [TestMethod]
    public async Task RejectsRecipientsNotArray()
    {
        //ParseRecipients (lines 340-343) requires the recipients value to open with '['.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = ReplaceRecipientsArray(general, "\"not-an-array\"");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A General JSON JWE whose 'recipients' is not an array must be rejected.");
    }


    [TestMethod]
    public async Task RejectsMalformedRecipientElementNotObject()
    {
        //ParseRecipients (lines 367-370): a recipients element that is not an object is rejected.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = ReplaceRecipientsArray(general, "[\"not-an-object\"]");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A 'recipients' element that is not an object must be rejected.");
    }


    [TestMethod]
    public async Task RejectsMalformedRecipientElementUnbalancedBraces()
    {
        //ParseRecipients (lines 403-406): the string-aware brace scanner reaches end-of-input
        //with depth != 0 when an element's braces are unbalanced. Two unclosed object opens leave
        //the depth counter positive even after the trailing document brace (the only '}' in the
        //appended tail) is consumed, so the scanner runs off the end with depth != 0.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = ReplaceRecipientsArray(general, "[{{");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A 'recipients' element with unbalanced braces must be rejected.");
    }


    [TestMethod]
    [DataRow("kid", DisplayName = "Recipient element missing header.kid")]
    [DataRow("encrypted_key", DisplayName = "Recipient element missing encrypted_key")]
    public async Task RejectsRecipientMissingKidOrEncryptedKey(string missing)
    {
        //ParseRecipients (lines 412-422): each element must carry both header.kid and
        //encrypted_key. Build a single-recipient array missing one of them.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);

        string element = string.Equals(missing, "kid", StringComparison.Ordinal)
            ? "[{\"header\":{},\"encrypted_key\":\"AAAA\"}]"
            : "[{\"header\":{\"kid\":\"did:example:r#k\"}}]";

        string mutated = ReplaceRecipientsArray(general, element);

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            $"A 'recipients' element missing its {missing} must be rejected.");
    }


    [TestMethod]
    public async Task RejectsAlgMismatch()
    {
        //ParseAndValidateHeader (lines 453-458): the embedded alg must equal the caller's
        //expected algorithm. The baseline carries ECDH-ES+A256KW; expect ECDH-1PU+A256KW.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);

        Assert.ThrowsExactly<FormatException>(() => GeneralJweParsing.ParseGeneralJson(
                general,
                WellKnownJweAlgorithms.Ecdh1PuA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "An embedded 'alg' that does not match the caller's expected algorithm must be rejected.");
    }


    [TestMethod]
    public async Task RejectsEncMismatch()
    {
        //ParseAndValidateHeader (lines 466-471): the embedded enc must equal the caller's
        //expected encryption. The baseline carries A256GCM; expect A256CBC-HS512.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);

        Assert.ThrowsExactly<FormatException>(() => GeneralJweParsing.ParseGeneralJson(
                general,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256CbcHs512,
                TestSetup.Base64UrlDecoder,
                Pool),
            "An embedded 'enc' that does not match the caller's expected encryption must be rejected.");
    }


    [TestMethod]
    public async Task RejectsDirectModeAlg()
    {
        //ParseAndValidateHeader mode gate (lines 490-496): JweAlgorithm.FromWellKnownName("ECDH-ES")
        //resolves to the DirectKeyAgreement descriptor (non-null), so the mode gate — not the
        //unknown-algorithm FormatException — fires, with NotSupportedException. The mode gate runs
        //before epk decoding, so the baseline epk does not need to be valid for this curve. Rewrite
        //the protected header's alg in place and expect the same bare ECDH-ES so the alg-match check
        //passes and execution reaches the mode gate.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = RewriteProtectedHeaderJsonValue(general, "alg", WellKnownJweAlgorithms.EcdhEs);

        Assert.ThrowsExactly<NotSupportedException>(() => GeneralJweParsing.ParseGeneralJson(
                mutated,
                WellKnownJweAlgorithms.EcdhEs,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "A bare ECDH-ES (Direct Key Agreement) alg is not implemented by the JSON serialization paths and must be rejected with NotSupportedException.");
    }


    [TestMethod]
    public async Task RejectsStandaloneKeyWrapAlg()
    {
        //ParseAndValidateHeader mode gate (lines 490-496): JweAlgorithm.FromWellKnownName("A256KW")
        //resolves to the KeyWrapping descriptor (non-null), so the mode gate fires with
        //NotSupportedException rather than the unknown-algorithm FormatException.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = RewriteProtectedHeaderJsonValue(general, "alg", WellKnownJweAlgorithms.A256Kw);

        Assert.ThrowsExactly<NotSupportedException>(() => GeneralJweParsing.ParseGeneralJson(
                mutated,
                WellKnownJweAlgorithms.A256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "A standalone A256KW (Key Wrapping) alg is not implemented by the JSON serialization paths and must be rejected with NotSupportedException.");
    }


    [TestMethod]
    public async Task RejectsDirectEncryptionDirAlg()
    {
        //The 'dir' (DirectEncryption) mode is resolved by JweAlgorithm.FromWellKnownName to a
        //non-null descriptor, so the mode gate rejects it with NotSupportedException — distinct
        //from the DirectKeyAgreement (ECDH-ES) and standalone KeyWrapping (A256KW) cases, proving
        //the gate is mode-wide. The expected alg is 'dir' so the alg-match passes to the gate.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = RewriteProtectedHeaderJsonValue(general, "alg", WellKnownJweAlgorithms.Dir);

        Assert.ThrowsExactly<NotSupportedException>(() => GeneralJweParsing.ParseGeneralJson(
                mutated,
                WellKnownJweAlgorithms.Dir,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "A 'dir' (Direct Encryption) alg is not implemented by the JSON serialization paths and must be rejected with NotSupportedException.");
    }


    [TestMethod]
    public async Task RejectsNameSharedBetweenProtectedAndUnprotected()
    {
        //RFC 7516 §5.2 step 4 / §7.2.1: the JOSE Header parameter names across the protected,
        //shared unprotected, and per-recipient header locations MUST be disjoint. 'cty' is a
        //non-cryptographic registered name, so it is not caught by the unprotected-cryptographic-
        //parameter gate; only the disjointness check rejects it appearing in both locations.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string withProtectedCty = InsertProtectedHeaderMember(general, "\"cty\":\"application/json\"");
        string mutated = InsertTopLevelMember(withProtectedCty, "\"unprotected\":{\"cty\":\"application/json\"}");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A header parameter ('cty') present in both the protected and unprotected headers must be rejected (RFC 7516 §7.2.1).");
    }


    [TestMethod]
    public async Task RejectsNameSharedBetweenProtectedAndRecipientHeader()
    {
        //The recipient header carries 'kid'; placing 'kid' in the protected header too makes the
        //two locations of that recipient's JOSE Header non-disjoint, which MUST be rejected.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = InsertProtectedHeaderMember(general, "\"kid\":\"did:example:recipient-0#key-1\"");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A header parameter ('kid') present in both the protected header and a recipient header must be rejected (RFC 7516 §7.2.1).");
    }


    [TestMethod]
    public async Task RejectsDuplicateEnvelopeMember()
    {
        //RFC 7516 §5.2 step 4: envelope members must be unique. The library reads members by
        //first occurrence, so a duplicated 'tag' would let a last-value parser diverge — the
        //same smuggling the protected-header duplicate gate closes, here at the envelope level.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = InsertTopLevelMember(general, "\"tag\":\"AAAAAAAAAAAAAAAAAAAAAA\"");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A duplicated top-level envelope member ('tag') must be rejected (RFC 7516 §5.2 step 4).");
    }


    [TestMethod]
    public async Task RejectsUnprotectedHeaderCarryingCryptographicParameter()
    {
        //RejectCryptographicParametersInUnprotectedHeader (lines 753-770): a Shared Unprotected
        //Header carrying a cryptographic parameter (here 'apu') is rejected; the library reads
        //cryptographic JOSE Header parameters only from the integrity-protected 'protected' header.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = InsertTopLevelMember(general, "\"unprotected\":{\"apu\":\"QWxpY2U\"}");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "An 'unprotected' header carrying the cryptographic parameter 'apu' must be rejected.");
    }


    [TestMethod]
    public async Task AcceptsUnprotectedHeaderWithBenignHint()
    {
        //The mirror of the rejection: an 'unprotected' carrying only a benign, non-cryptographic
        //hint ('jku') is permitted, exactly as the ECDH-1PU Appendix B vector carries 'jku' in
        //unprotected and decrypts. The message must parse without throwing.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = InsertTopLevelMember(general, "\"unprotected\":{\"jku\":\"https://alice.example.com/keys.jwks\"}");

        using AeadGeneralMessage parsed = ParseAnoncrypt(mutated);

        Assert.HasCount(1, parsed.Recipients,
            "An 'unprotected' carrying only a benign 'jku' hint must not be rejected on that basis.");
    }


    [TestMethod]
    public async Task RejectsIvLengthMismatch()
    {
        //DecodeAndValidateContentParts (lines 701-706): the decoded IV length must equal the
        //declared enc's IvByteLength (12 for A256GCM). Replace the iv with a base64url value that
        //decodes to a different length.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        //"AAAAAAAAAAAAAAAAAAAAAA" base64url decodes to 16 bytes, not the 12 A256GCM requires.
        string mutated = ReplaceTopLevelStringValue(general, "iv", "AAAAAAAAAAAAAAAAAAAAAA");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "An 'iv' whose decoded length does not match the enc's IV length must be rejected (RFC 7516 §5.2).");
    }


    [TestMethod]
    public async Task RejectsTagLengthMismatch()
    {
        //DecodeAndValidateContentParts (lines 708-713): the decoded tag length must equal the
        //declared enc's TagByteLength (16 for A256GCM). Replace the tag with a base64url value
        //that decodes to a different length.
        string general = await EncryptAnoncryptSingleRecipientJsonAsync().ConfigureAwait(false);
        //"AAAAAAAA" base64url decodes to 6 bytes, not the 16 A256GCM requires.
        string mutated = ReplaceTopLevelStringValue(general, "tag", "AAAAAAAA");

        Assert.ThrowsExactly<FormatException>(() => ParseAnoncrypt(mutated),
            "A 'tag' whose decoded length does not match the enc's tag length must be rejected (RFC 7516 §5.2).");
    }


    [TestMethod]
    public async Task RejectsEpkPointNotOnCurve()
    {
        //DecodeAndValidateEpk (lines 626-631): a P-256 epk whose (x, y) is not on the curve is
        //rejected, citing the possible invalid-curve attack. Encrypt a P-256 anoncrypt baseline,
        //then flip the first base64url character of the epk 'y' coordinate so the point leaves
        //the curve while remaining the same length.
        string general = await EncryptAnoncryptP256SingleRecipientJsonAsync().ConfigureAwait(false);
        string mutated = TamperProtectedHeaderEpkY(general);

        Assert.ThrowsExactly<FormatException>(() => GeneralJweParsing.ParseGeneralJson(
                mutated,
                WellKnownJweAlgorithms.EcdhEsA256Kw,
                WellKnownJweEncryptionAlgorithms.A256Gcm,
                TestSetup.Base64UrlDecoder,
                Pool),
            "A P-256 epk whose point is not on the curve must be rejected as a possible invalid-curve attack.");
    }


    [TestMethod]
    public async Task RecipientScanner_HandlesEscapedQuoteAndNestedObjectInKid()
    {
        //The recipients brace/string scanner (ParseRecipients, lines 375-401) must skip string
        //content so an escaped quote inside a kid and a benign nested object elsewhere in the
        //element do not bias the depth counter. Build a single-recipient array whose header carries
        //both, plus the real encrypted_key from the baseline so the message remains decryptable.
        AnoncryptSingleRecipientP256 baseline = await EncryptAnoncryptP256BaselineAsync().ConfigureAwait(false);

        try
        {
            string general = baseline.Message.ToGeneralJson(TestSetup.Base64UrlEncoder);
            string encryptedKey = ExtractRecipientEncryptedKey(general);

            const string trickyKid = "did:example:r#key-\\\"-x";
            string element =
                "[{\"header\":{\"kid\":\"" + trickyKid + "\",\"extra\":{\"nested\":\"value\"}},"
                + "\"encrypted_key\":\"" + encryptedKey + "\"}]";
            string mutated = ReplaceRecipientsArray(general, element);

            using AeadGeneralMessage parsed = ParseAnoncrypt(mutated);

            Assert.HasCount(1, parsed.Recipients, "The scanner must extract exactly one recipient.");
            //The decoded kid carries the unescaped quote: the JSON reader decodes \" to ".
            Assert.AreEqual("did:example:r#key-\"-x", parsed.Recipients[0].KeyId,
                "The scanner must extract the kid past the escaped quote and the benign nested object.");

            using DecryptedContent decrypted = await parsed.DecryptAnoncryptAsync(
                "did:example:r#key-\"-x",
                baseline.RecipientPrivateKey,
                MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                ConcatKdf.DefaultKeyDerivationDelegate,
                MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
                MicrosoftKeyAgreementFunctions.AesGcmDecryptAsync,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(decrypted.AsReadOnlySpan().SequenceEqual(Plaintext),
                "The re-keyed single-recipient message must still decrypt to the original plaintext.");
        }
        finally
        {
            baseline.DisposeKeys();
        }
    }


    //Parses with the anoncrypt baseline's policy (ECDH-ES+A256KW / A256GCM).
    private static AeadGeneralMessage ParseAnoncrypt(string generalJson) =>
        GeneralJweParsing.ParseGeneralJson(
            generalJson,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            TestSetup.Base64UrlDecoder,
            Pool);


    //Encrypts an X25519 anoncrypt single-recipient message and returns only its General JSON. The
    //recipient key material is disposed before returning; the rejection tests never decrypt.
    private async Task<string> EncryptAnoncryptSingleRecipientJsonAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = BouncyCastleKeyMaterialCreator.CreateX25519Keys(Pool);
        using PublicKeyMemory recipientPublic = recipient.PublicKey;
        using PrivateKeyMemory recipientPrivate = recipient.PrivateKey;

        using GeneralJweMessage message = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
            Plaintext,
            new List<GeneralJweRecipientInput> { new(RecipientKid, recipientPublic) },
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            protectedHeaderExtras: null,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            BouncyCastleKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptX25519Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return message.ToGeneralJson(TestSetup.Base64UrlEncoder);
    }


    //Encrypts a P-256 anoncrypt single-recipient message (so the epk is an EC point with x and y)
    //and returns only its General JSON. Used by the invalid-curve test, which needs a y coordinate.
    private async Task<string> EncryptAnoncryptP256SingleRecipientJsonAsync()
    {
        AnoncryptSingleRecipientP256 baseline = await EncryptAnoncryptP256BaselineAsync().ConfigureAwait(false);
        try
        {
            return baseline.Message.ToGeneralJson(TestSetup.Base64UrlEncoder);
        }
        finally
        {
            baseline.DisposeKeys();
        }
    }


    //Encrypts a P-256 anoncrypt single-recipient baseline and hands back the message plus the
    //recipient private key so a caller can decrypt. The caller disposes via DisposeKeys.
    private async Task<AnoncryptSingleRecipientP256> EncryptAnoncryptP256BaselineAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);
        using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
        using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> recipient = MicrosoftKeyMaterialCreator.CreateP256ExchangeKeys(Pool);

        GeneralJweMessage message = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
            Plaintext,
            new List<GeneralJweRecipientInput> { new(RecipientKid, recipient.PublicKey) },
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            protectedHeaderExtras: null,
            new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
            JwtHeaderSerializer,
            TestSetup.Base64UrlEncoder,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            MicrosoftEntropyFunctions.GenerateNonce,
            MicrosoftKeyAgreementFunctions.EcdhEsMultiRecipientAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
            MicrosoftKeyAgreementFunctions.AesGcmEncryptAsync,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return new AnoncryptSingleRecipientP256(message, recipient.PublicKey, recipient.PrivateKey);
    }


    //Removes a top-level string member ("<member>":"<value>") together with one adjacent comma.
    //The serializer emits members in a fixed order with no insignificant whitespace, so this is
    //an exact excision.
    private static string RemoveTopLevelStringMember(string json, string member)
    {
        string token = $"\"{member}\":";
        int memberStart = json.IndexOf(token, StringComparison.Ordinal);
        int valueQuoteStart = json.IndexOf('"', memberStart + token.Length);
        int valueQuoteEnd = json.IndexOf('"', valueQuoteStart + 1);
        int afterValue = valueQuoteEnd + 1;

        if(afterValue < json.Length && json[afterValue] == ',')
        {
            return json[..memberStart] + json[(afterValue + 1)..];
        }

        int commaPrev = json.LastIndexOf(',', memberStart);

        return json[..commaPrev] + json[afterValue..];
    }


    //Replaces the value of a top-level string member with a new raw (already-base64url) value.
    private static string ReplaceTopLevelStringValue(string json, string member, string newValue)
    {
        string token = $"\"{member}\":\"";
        int valueStart = json.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = json.IndexOf('"', valueStart);

        return json[..valueStart] + newValue + json[valueEnd..];
    }


    //Replaces the entire "recipients":[...] array value with the supplied replacement text. The
    //replacement is the raw JSON to follow "recipients": (an array, a string, anything). The
    //array extent is found with a string-aware bracket scan so quoted brackets do not mislead it.
    private static string ReplaceRecipientsArray(string json, string replacement)
    {
        const string token = "\"recipients\":";
        int valueStart = json.IndexOf(token, StringComparison.Ordinal) + token.Length;

        //The baseline always emits an array here; find its balanced extent.
        int pos = valueStart;
        if(json[pos] != '[')
        {
            //Defensive: should not happen for the fixed-shape baseline.
            throw new InvalidOperationException("Baseline 'recipients' value is not an array.");
        }

        int depth = 0;
        bool inString = false;
        for(; pos < json.Length; pos++)
        {
            char c = json[pos];
            if(inString)
            {
                if(c == '\\')
                {
                    pos++;
                }
                else if(c == '"')
                {
                    inString = false;
                }

                continue;
            }

            if(c == '"')
            {
                inString = true;
            }
            else if(c == '[')
            {
                depth++;
            }
            else if(c == ']')
            {
                depth--;
                if(depth == 0)
                {
                    break;
                }
            }
        }

        int arrayEnd = pos + 1;

        return json[..valueStart] + replacement + json[arrayEnd..];
    }


    //Inserts a raw top-level member immediately after the opening brace.
    private static string InsertTopLevelMember(string json, string rawMember) =>
        "{" + rawMember + "," + json[1..];


    //Decodes the base64url "protected" header, inserts a raw member immediately after its opening
    //brace, and re-encodes it back into the "protected" envelope member.
    private static string InsertProtectedHeaderMember(string generalJson, string rawMember)
    {
        string headerJson = DecodeProtectedHeader(generalJson, out string protectedEncoded);
        string newHeaderJson = "{" + rawMember + "," + headerJson[1..];
        string newProtectedEncoded = EncodeProtectedHeader(newHeaderJson);

        return generalJson.Replace(
            $"\"protected\":\"{protectedEncoded}\"",
            $"\"protected\":\"{newProtectedEncoded}\"",
            StringComparison.Ordinal);
    }


    //Extracts the (single) recipient's encrypted_key raw base64url value from a General JSON.
    private static string ExtractRecipientEncryptedKey(string json)
    {
        const string token = "\"encrypted_key\":\"";
        int valueStart = json.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = json.IndexOf('"', valueStart);

        return json[valueStart..valueEnd];
    }


    //Decodes the base64url "protected" header, replaces the JSON string value of a top-level
    //member inside it (alg/enc), and re-encodes the header back into the "protected" member.
    //The replaced value is a raw string (no surrounding quotes); only string-valued members are
    //handled, which is what alg/enc are.
    private static string RewriteProtectedHeaderJsonValue(string generalJson, string member, string newValue)
    {
        string headerJson = DecodeProtectedHeader(generalJson, out string protectedEncoded);
        string newHeaderJson = ReplaceTopLevelStringValue(headerJson, member, newValue);
        string newProtectedEncoded = EncodeProtectedHeader(newHeaderJson);

        return generalJson.Replace(
            $"\"protected\":\"{protectedEncoded}\"",
            $"\"protected\":\"{newProtectedEncoded}\"",
            StringComparison.Ordinal);
    }


    //Flips the first base64url character of the epk 'y' coordinate inside the decoded protected
    //header so the EC point leaves the curve, then re-encodes the header. The y value keeps its
    //length, so only the on-curve check (not a structural length check) fails.
    private static string TamperProtectedHeaderEpkY(string generalJson)
    {
        string headerJson = DecodeProtectedHeader(generalJson, out string protectedEncoded);

        //epk is a nested object: ..."y":"<base64url>"...; flip the first char of its value.
        const string token = "\"y\":\"";
        int valueStart = headerJson.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = headerJson.IndexOf('"', valueStart);
        char[] value = headerJson[valueStart..valueEnd].ToCharArray();
        value[0] = value[0] == 'A' ? 'B' : 'A';
        string tamperedHeaderJson = headerJson[..valueStart] + new string(value) + headerJson[valueEnd..];

        string newProtectedEncoded = EncodeProtectedHeader(tamperedHeaderJson);

        return generalJson.Replace(
            $"\"protected\":\"{protectedEncoded}\"",
            $"\"protected\":\"{newProtectedEncoded}\"",
            StringComparison.Ordinal);
    }


    private static string DecodeProtectedHeader(string generalJson, out string protectedEncoded)
    {
        const string token = "\"protected\":\"";
        int valueStart = generalJson.IndexOf(token, StringComparison.Ordinal) + token.Length;
        int valueEnd = generalJson.IndexOf('"', valueStart);
        protectedEncoded = generalJson[valueStart..valueEnd];

        using IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(protectedEncoded, Pool);

        return Encoding.UTF8.GetString(decoded.Memory.Span);
    }


    private static string EncodeProtectedHeader(string headerJson)
    {
        byte[] headerBytes = Encoding.UTF8.GetBytes(headerJson);

        return TestSetup.Base64UrlEncoder(headerBytes);
    }


    //A P-256 anoncrypt single-recipient baseline plus its recipient key material.
    private sealed class AnoncryptSingleRecipientP256
    {
        private readonly PublicKeyMemory recipientPublic;
        private readonly PrivateKeyMemory recipientPrivate;
        private bool isPrivateConsumed;

        public AnoncryptSingleRecipientP256(
            GeneralJweMessage message,
            PublicKeyMemory recipientPublic,
            PrivateKeyMemory recipientPrivate)
        {
            Message = message;
            this.recipientPublic = recipientPublic;
            this.recipientPrivate = recipientPrivate;
        }

        public GeneralJweMessage Message { get; }

        public PrivateKeyMemory RecipientPrivateKey
        {
            get
            {
                isPrivateConsumed = true;

                return recipientPrivate;
            }
        }

        public void DisposeKeys()
        {
            Message.Dispose();
            recipientPublic.Dispose();
            if(!isPrivateConsumed)
            {
                recipientPrivate.Dispose();
            }
        }
    }
}
