using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for the <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/>,
/// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/>,
/// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/> and
/// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
/// key-selection combinators over a JWK Set's <c>keys</c> array.
/// </summary>
[TestClass]
internal sealed class JwkJsonReaderKeySelectionTests
{
    private static byte[] Utf8(string text) =>
        Encoding.UTF8.GetBytes(text);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>: <c>kid</c>
    /// identifies a key so a caller can select it out of a set; a matching identifier selects that key.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdSelectsTheMatchingKey()
    {
        string json = """{"keys":[{"kty":"EC","kid":"a"},{"kty":"EC","kid":"b"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "b");

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
        Assert.AreEqual("b", result.Members?["kid"]);
        Assert.AreEqual("EC", result.Members?["kty"]);
    }


    /// <summary>No key in the set carries the requested <c>kid</c>.</summary>
    [TestMethod]
    public void SelectKeyByKeyIdReportsNoMatchWhenNoKeyCarriesTheKeyId()
    {
        string json = """{"keys":[{"kty":"EC","kid":"a"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "does-not-exist");

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// distinct <c>kid</c> values within a set a SHOULD, and names keys of differing <c>kty</c> that
    /// an application treats as equivalent alternatives as a legitimate duplicate — the shape this
    /// set carries. Selection refuses it rather than yielding whichever element the array lists
    /// first, leaving the choice between alternatives to a caller that can make it.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdReportsMultipleKeysMatchedOnADuplicateKeyId()
    {
        string json = """{"keys":[{"kty":"EC","kid":"dup"},{"kty":"RSA","kid":"dup"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "dup");

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>An absent or empty key identifier is never a match — never a wildcard for the first key.</summary>
    [TestMethod]
    public void SelectKeyByKeyIdReportsKeyIdRequiredWhenNoIdentifierIsSupplied()
    {
        string json = """{"keys":[{"kty":"EC","kid":"a"}]}""";

        JwkSelectionResult nullResult = JwkJsonReader.SelectKeyByKeyId(Utf8(json), null);
        JwkSelectionResult emptyResult = JwkJsonReader.SelectKeyByKeyId(Utf8(json), string.Empty);

        Assert.AreEqual(JwkSelectionOutcome.KeyIdRequired, nullResult.Outcome);
        Assert.AreEqual(JwkSelectionOutcome.KeyIdRequired, emptyResult.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> optional: a set with exactly one key selects it with no identifier required.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeySelectsTheOnlyKeyInTheSet()
    {
        string json = """{"keys":[{"kty":"OKP","crv":"Ed25519","x":"abc"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(json));

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
        Assert.AreEqual("Ed25519", result.Members?["crv"]);
    }


    /// <summary>Two or more keys is a refusal — never a default to whichever key sits first.</summary>
    [TestMethod]
    public void SelectSoleKeyReportsMultipleKeysMatchedOnTwoKeys()
    {
        string json = """{"keys":[{"kty":"EC","kid":"a"},{"kty":"EC","kid":"b"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(json));

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>An empty <c>keys</c> array carries no key to select.</summary>
    [TestMethod]
    public void SelectSoleKeyReportsNoMatchOnAnEmptySet()
    {
        string json = """{"keys":[]}""";

        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(json));

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>: a document is
    /// refused before any key is scanned when it is not well formed, here on a repeated member name.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdReportsMalformedDocumentOnARepeatedMemberName()
    {
        string json = """{"keys":[{"kty":"EC","kty":"RSA","kid":"a"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "a");

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>The same malformed-document gate applies to <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/>.</summary>
    [TestMethod]
    public void SelectSoleKeyReportsMalformedDocumentOnATruncatedDocument()
    {
        string json = """{"keys":[{"kty":"EC\""";

        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(json));

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    private static string DocOneSigOneEnc => """{"keys":[{"kty":"EC","kid":"k1","use":"sig"},{"kty":"EC","kid":"k2","use":"enc"}]}""";

    private static string DocSameKidSigThenEnc => """{"keys":[{"kty":"EC","kid":"dup","use":"sig"},{"kty":"EC","kid":"dup","use":"enc"}]}""";

    private static string DocSameKidEncThenSig => """{"keys":[{"kty":"EC","kid":"dup","use":"enc"},{"kty":"EC","kid":"dup","use":"sig"}]}""";

    private static string DocEscapedUseNameEnc => "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"\\u0075se\":\"enc\"}]}";

    private static string DocEscapedUseValueSig => "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"use\":\"\\u0073ig\"}]}";

    private static string DocEscapedKeysMemberName => "{\"\\u006beys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"use\":\"sig\"}]}";

    private static string DocEscapedKidMemberName => "{\"keys\":[{\"kty\":\"EC\",\"\\u006bid\":\"k\",\"use\":\"sig\"}]}";

    private static string DocPrivateD => """{"keys":[{"kty":"EC","kid":"k","use":"sig","d":"secret"}]}""";

    private static string DocNonObjectBeforeMatch => """{"keys":[null,{"kty":"EC","kid":"k","use":"sig"}]}""";

    private static string DocDuplicateDecodedUseMember => "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"use\":\"sig\",\"\\u0075se\":\"enc\"}]}";


    /// <summary>
    /// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/> counts every element toward its
    /// one-key requirement whatever its <c>use</c>, so a set holding one signature and one encryption
    /// key is refused for carrying two keys.
    /// </summary>
    [TestMethod]
    public void PinSelectSoleKeyReportsMultipleKeysMatchedOnOneSigAndOneEncKey()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocOneSigOneEnc));

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> refuses a duplicate
    /// <c>kid</c> regardless of order or of each element's <c>use</c>.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdReportsMultipleKeysMatchedOnADuplicateKeyIdWithDifferingUse()
    {
        JwkSelectionResult sigThenEnc = JwkJsonReader.SelectKeyByKeyId(Utf8(DocSameKidSigThenEnc), "dup");
        JwkSelectionResult encThenSig = JwkJsonReader.SelectKeyByKeyId(Utf8(DocSameKidEncThenSig), "dup");

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, sigThenEnc.Outcome);
        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, encThenSig.Outcome);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> compares member names
    /// as raw bytes, so an escaped spelling of <c>use</c> is invisible to it; the member is not
    /// recognised as <c>use</c> at all, and selection proceeds exactly as if it were an unrelated,
    /// unread member.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdIgnoresAnEscapedUseMemberName()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocEscapedUseNameEnc), "k");

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> reads no <c>use</c>
    /// member at all, escaped value or not.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdIgnoresAnEscapedUseMemberValue()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocEscapedUseValueSig), "k");

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte})"/>'s lookup of the <c>keys</c>
    /// member compares raw bytes, so an escaped spelling of <c>keys</c> is not found and the set reads
    /// as if it carried no <c>keys</c> array.
    /// </summary>
    [TestMethod]
    public void PinSelectSoleKeyReportsNoMatchWhenTheKeysMemberNameIsEscaped()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocEscapedKeysMemberName));

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// An escaped <c>kid</c> member name is not found by
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/>'s raw-byte key
    /// lookup, so a request for that key's plain-spelled identifier reports no match.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdReportsNoMatchWhenTheKidMemberNameIsEscaped()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocEscapedKidMemberName), "k");

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> reads no
    /// private-material member at all; a <c>d</c>-bearing key is selected like any other.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdSelectsAKeyThatCarriesAPrivateMember()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocPrivateD), "k");

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
        Assert.AreEqual("secret", result.Members?["d"]);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/>'s element walk stops
    /// at the first non-object element rather than refusing the document, so a match after a leading
    /// <see langword="null"/> element is missed.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdReportsNoMatchWhenANonObjectElementPrecedesTheMatch()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocNonObjectBeforeMatch), "k");

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> refuses a decoded-duplicate member name —
    /// a plain and an escaped spelling of <c>use</c> in the same object — so this document is
    /// <see cref="JwkSelectionOutcome.MalformedDocument"/> under
    /// <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?)"/> too.
    /// </summary>
    [TestMethod]
    public void PinSelectKeyByKeyIdReportsMalformedDocumentOnADecodedDuplicateUseMember()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocDuplicateDecodedUseMember), "k");

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    private static string DocUseDifferentOnOnlyKidMatch => """{"keys":[{"kty":"EC","kid":"k","use":"enc"}]}""";

    private static string DocUseNumber => """{"keys":[{"kty":"EC","kid":"k","use":5}]}""";

    private static string DocUseArray => """{"keys":[{"kty":"EC","kid":"k","use":["sig"]}]}""";

    private static string DocUseObject => """{"keys":[{"kty":"EC","kid":"k","use":{"x":"sig"}}]}""";

    private static string DocUseNull => """{"keys":[{"kty":"EC","kid":"k","use":null}]}""";

    private static string DocPlainSigAndEscapedSig => "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k1\",\"use\":\"sig\"},{\"kty\":\"EC\",\"kid\":\"k2\",\"use\":\"\\u0073ig\"}]}";

    private static string DocUseUpperCaseSig => """{"keys":[{"kty":"EC","kid":"k","use":"SIG"}]}""";

    private static string DocNonObjectBetweenMatches => """{"keys":[{"kty":"EC","kid":"k1","use":"sig"},42,{"kty":"EC","kid":"k2","use":"sig"}]}""";

    private static string DocNonObjectBeforePrivateBearingElement => """{"keys":["not-an-object",{"kty":"EC","kid":"k","use":"sig","d":"secret"}]}""";

    private static string DocNestedArrayElement => """{"keys":[{"kty":"EC","kid":"k1","use":"sig"},["nested"],{"kty":"EC","kid":"k2","use":"sig"}]}""";

    private static string DocPrivateK => """{"keys":[{"kty":"oct","kid":"k","use":"sig","k":"secret"}]}""";

    private static string DocPrivateOthArrayNoD => """{"keys":[{"kty":"RSA","kid":"k","use":"sig","oth":[{"r":"1"}]}]}""";

    private static string DocPrivateEscapedD => "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"use\":\"sig\",\"\\u0064\":\"secret\"}]}";

    private static string DocNonEligiblePrivateOtherKid => """{"keys":[{"kty":"EC","kid":"other","use":"sig","d":"secret"},{"kty":"EC","kid":"k","use":"sig"}]}""";

    private static string DocNonEligiblePrivateEncUse => """{"keys":[{"kty":"EC","kid":"k","use":"enc","d":"secret"}]}""";

    private static string DocCleanThenPrivate => """{"keys":[{"kty":"EC","kid":"clean","use":"sig"},{"kty":"EC","kid":"other","use":"sig","d":"secret"}]}""";

    private static string DocPrivateThenClean => """{"keys":[{"kty":"EC","kid":"other","use":"sig","d":"secret"},{"kty":"EC","kid":"clean","use":"sig"}]}""";

    private static string DocTwoCleanThenPrivate => """{"keys":[{"kty":"EC","kid":"k1","use":"sig"},{"kty":"EC","kid":"k2","use":"sig"},{"kty":"EC","kid":"other","use":"sig","d":"secret"}]}""";

    private static string DocTwoCleanNoPrivate => """{"keys":[{"kty":"EC","kid":"k1","use":"sig"},{"kty":"EC","kid":"k2","use":"sig"}]}""";

    private static string DocTrailingContent => """{"keys":[{"kty":"EC","kid":"k","use":"sig"}]}garbage""";

    private static string DocPrivateEscapedKUpperCaseHex => "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k\",\"use\":\"sig\",\"\\u006B\":\"secret\"}]}";

    private static string DocUseEncEscapedWithUpperCaseHex => "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"use\":\"e\\u006Ec\"}]}";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: use of the
    /// <c>use</c> member is OPTIONAL, so a key with no <c>use</c> at all is eligible.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterSelectsWhenUseIsAbsent()
    {
        string json = """{"keys":[{"kty":"EC","kid":"k"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: a <c>use</c>
    /// present as a JSON string equal to the requested value is eligible.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterSelectsWhenUseEqualsTheRequestedValue()
    {
        string json = """{"keys":[{"kty":"EC","kid":"k","use":"sig"}]}""";

        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// A different <c>use</c> on the sole <c>kid</c> match makes it ineligible: the key exists but
    /// is not one this caller may select, so the result is <see cref="JwkSelectionOutcome.NoMatch"/>,
    /// not a refusal that could be confused with the identifier itself being absent from the set.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsNoMatchWhenUseDiffersOnTheOnlyKidMatch()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocUseDifferentOnOnlyKidMatch), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// The filter earns its keep in sole-key mode: a set holding one <c>sig</c> and one <c>enc</c> key
    /// selects the <c>sig</c> key, where the unfiltered selector refuses the same document outright.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterSelectsTheSigKeyWhereTheUnfilteredSelectorRefuses()
    {
        JwkSelectionResult unfiltered = JwkJsonReader.SelectSoleKey(Utf8(DocOneSigOneEnc));
        JwkSelectionResult filtered = JwkJsonReader.SelectSoleKey(Utf8(DocOneSigOneEnc), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, unfiltered.Outcome);
        Assert.AreEqual(JwkSelectionOutcome.Selected, filtered.Outcome);
        Assert.AreEqual("k1", filtered.Members?["kid"]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// distinct <c>kid</c> values a SHOULD; a duplicate is refused regardless of order and whatever
    /// each duplicate's <c>use</c> is — <c>use</c> never narrows the duplicate-<c>kid</c> refusal.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMultipleKeysMatchedOnADuplicateKeyIdWithDifferingUseSigThenEnc()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocSameKidSigThenEnc), "dup", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>: the same
    /// refusal holds with the duplicate's elements in the opposite array order.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMultipleKeysMatchedOnADuplicateKeyIdWithDifferingUseEncThenSig()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocSameKidEncThenSig), "dup", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: a <c>use</c>
    /// present as a JSON number is not the JSON string this library compares, so the key is
    /// ineligible.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsNoMatchWhenUseIsANumber()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocUseNumber), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: a <c>use</c>
    /// present as a JSON array is not a JSON string, so the key is ineligible.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsNoMatchWhenUseIsAnArray()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocUseArray), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: a <c>use</c>
    /// present as a JSON object is not a JSON string, so the key is ineligible.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsNoMatchWhenUseIsAnObject()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocUseObject), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: a <c>use</c>
    /// present as JSON <see langword="null"/> is not a JSON string, so the key is ineligible.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsNoMatchWhenUseIsJsonNull()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocUseNull), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// A member spelled with a JSON escape in its NAME (<c>\u0075se</c> decodes to <c>use</c>) is
    /// seen exactly as the plain spelling: the key carries <c>use</c>: <c>enc</c> and is ineligible
    /// for <c>sig</c>.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsNoMatchWhenTheUseMemberNameIsEscaped()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocEscapedUseNameEnc), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-6">RFC 7517 §6</see> adopts
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.3">RFC 7515 §5.3</see>: the same
    /// comparison rule applies to member names AND member values compared against known strings.
    /// A <c>use</c> value spelled with a JSON escape (<c>\u0073ig</c> decodes to <c>sig</c>) is the
    /// value <c>sig</c>, and the key is eligible.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterSelectsWhenTheUseValueIsAnEscapedSpellingOfTheRequestedValue()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocEscapedUseValueSig), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// A plain <c>sig</c> key beside a key whose <c>use</c> is an escaped spelling of <c>sig</c> are
    /// both eligible, so sole-key mode refuses the set as carrying more than one candidate.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMultipleKeysMatchedWhenAPlainAndAnEscapedSigKeyBothQualify()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocPlainSigAndEscapedSig), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: the
    /// <c>use</c> value is case-sensitive, so <c>SIG</c> is not the requested value <c>sig</c>.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsNoMatchWhenUseDiffersOnlyInCase()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocUseUpperCaseSig), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.NoMatch, result.Outcome);
    }


    /// <summary>
    /// The filtered walk locates the <c>keys</c> array by its DECODED name too, so an escaped
    /// spelling of <c>keys</c> is read exactly as the plain spelling — unlike the unfiltered
    /// selector, pinned above, which misses it.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterSelectsWhenTheKeysMemberNameIsEscaped()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocEscapedKeysMemberName), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.3">RFC 7515 §5.3</see>: an escaped
    /// spelling of <c>kid</c> is read exactly as the plain spelling.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterSelectsWhenTheKidMemberNameIsEscaped()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocEscapedKidMemberName), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: the value
    /// of <c>keys</c> is an array of JWK VALUES, and a JWK is an object; a non-object element ahead of
    /// a match would otherwise hide it, so the filtered walk refuses the whole document instead.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMalformedDocumentOnANullElementBeforeAMatch()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocNonObjectBeforeMatch), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: the same
    /// refusal applies to <see cref="JwkJsonReader.SelectKeyByKeyId(ReadOnlySpan{byte}, string?, ReadOnlySpan{byte})"/> on a <see langword="null"/> element.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMalformedDocumentOnANullElementBeforeAMatch()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocNonObjectBeforeMatch), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: a number
    /// element between two matches is refused by both filtered overloads.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMalformedDocumentOnANumberElementBetweenMatches()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocNonObjectBetweenMatches), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: the same
    /// number-element document is refused in <c>kid</c> mode.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMalformedDocumentOnANumberElementBetweenMatches()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocNonObjectBetweenMatches), "k1", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: a
    /// non-object element ahead of a private-bearing element is refused before the private-material
    /// scan would otherwise reach it, from both filtered overloads.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMalformedDocumentOnAStringElementBeforeAPrivateBearingElement()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocNonObjectBeforePrivateBearingElement), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: the same
    /// document is refused in <c>kid</c> mode.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMalformedDocumentOnAStringElementBeforeAPrivateBearingElement()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocNonObjectBeforePrivateBearingElement), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: a nested
    /// array standing where a JWK object is expected is refused by both filtered overloads.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMalformedDocumentOnANestedArrayElement()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocNestedArrayElement), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>: the same
    /// nested-array document is refused in <c>kid</c> mode.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMalformedDocumentOnANestedArrayElement()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocNestedArrayElement), "k1", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>: a decoded
    /// duplicate member name — a plain and an escaped spelling of <c>use</c> in one object — is
    /// refused before any element is scanned for eligibility, from both filtered overloads.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMalformedDocumentOnADecodedDuplicateUseMember()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocDuplicateDecodedUseMember), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>The same decoded-duplicate document is refused in <c>kid</c> mode.</summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMalformedDocumentOnADecodedDuplicateUseMember()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocDuplicateDecodedUseMember), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
    }


    /// <summary>
    /// A missing key identifier is refused before the set is scanned at all, even when the set
    /// carries private material — <see cref="JwkSelectionOutcome.KeyIdRequired"/> outranks
    /// <see cref="JwkSelectionOutcome.PrivateOrSymmetricMemberPresent"/>.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsKeyIdRequiredEvenWhenTheSetCarriesPrivateMaterial()
    {
        JwkSelectionResult nullResult = JwkJsonReader.SelectKeyByKeyId(Utf8(DocPrivateD), null, WellKnownJwkValues.UseSigUtf8);
        JwkSelectionResult emptyResult = JwkJsonReader.SelectKeyByKeyId(Utf8(DocPrivateD), string.Empty, WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.KeyIdRequired, nullResult.Outcome);
        Assert.AreEqual(JwkSelectionOutcome.KeyIdRequired, emptyResult.Outcome);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// an element carrying the EC/OKP private scalar <c>d</c> refuses the whole set.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsPrivateOrSymmetricMemberPresentForAnElementCarryingD()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocPrivateD), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// an <c>oct</c> key's symmetric value <c>k</c> (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.4.1">RFC
    /// 7518 §6.4.1</see>) refuses the whole set the same way <c>d</c> does.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentForAnElementCarryingK()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocPrivateK), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7">RFC 7518 §6.3.2.7</see>: an
    /// RSA private key's <c>oth</c> (other primes info) is an ARRAY member; the refusal works off
    /// its NAME, whatever its JSON type, so it refuses even without a <c>d</c> member alongside it.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentForAnElementCarryingOthWithNoD()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocPrivateOthArrayNoD), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC: an
    /// escaped spelling of the private member name <c>d</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.3">RFC 7515 §5.3</see>) is read
    /// exactly as the plain spelling, so it refuses the set the same way an unescaped <c>d</c> does.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentForAnEscapedDMemberName()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocPrivateEscapedD), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// the refusal is SET-WIDE, so an unrelated element (a different <c>kid</c>) that carries <c>d</c>
    /// refuses the selection of an otherwise clean, matching key.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsPrivateOrSymmetricMemberPresentWhenAnUnrelatedElementCarriesD()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocNonEligiblePrivateOtherKid), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// the refusal fires even for an element that is itself ineligible on <c>use</c> — the set-wide
    /// refusal does not require the private-bearing element to be a candidate.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentForAnIneligibleElementCarryingD()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocNonEligiblePrivateEncUse), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// precedence — a clean match followed by a private-bearing element still refuses.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentWhenACleanMatchPrecedesIt()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocCleanThenPrivate), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// precedence — a private-bearing element followed by a clean match still refuses.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentWhenACleanMatchFollowsIt()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocPrivateThenClean), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// precedence — the private-material refusal outranks
    /// <see cref="JwkSelectionOutcome.MultipleKeysMatched"/>, so two clean, eligible matches plus a
    /// private-bearing element still refuse as private material.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentOverTwoCleanMatches()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocTwoCleanThenPrivate), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>: with no
    /// private material, two clean eligible matches are refused as
    /// <see cref="JwkSelectionOutcome.MultipleKeysMatched"/>, not as private material.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMultipleKeysMatchedForTwoCleanEligibleMatchesAndNoPrivateMaterial()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocTwoCleanNoPrivate), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MultipleKeysMatched, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>An empty <c>use</c> filter is a caller error, not a query with no eligible keys.</summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterThrowsOnAnEmptyPublicKeyUse()
    {
        _ = Assert.Throws<ArgumentException>(
            () => JwkJsonReader.SelectKeyByKeyId(Utf8(DocPrivateD), "k", ReadOnlySpan<byte>.Empty));
    }


    /// <summary>The same argument check applies to <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.</summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterThrowsOnAnEmptyPublicKeyUse()
    {
        _ = Assert.Throws<ArgumentException>(
            () => JwkJsonReader.SelectSoleKey(Utf8(DocPrivateD), ReadOnlySpan<byte>.Empty));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 §2</see>: a JSON text is
    /// the whole input; content trailing an otherwise well-formed document is refused before any
    /// element is scanned, from the <c>kid</c>-mode filtered overload.
    /// </summary>
    [TestMethod]
    public void SelectKeyByKeyIdWithUseFilterReportsMalformedDocumentOnTrailingContent()
    {
        JwkSelectionResult result = JwkJsonReader.SelectKeyByKeyId(Utf8(DocTrailingContent), "k", WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 §2</see>: the same
    /// trailing-content document is refused from the sole-key-mode filtered overload.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsMalformedDocumentOnTrailingContent()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocTrailingContent), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.MalformedDocument, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// This library's own policy for a JWK Set of verification keys, not a requirement of any RFC:
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.3">RFC 7515 §5.3</see> hex escapes
    /// decode the same whichever case their digits are written in — a private member name spelled as
    /// the private member <c>k</c>'s four-digit escape, its hex digit for eleven written as an
    /// upper-case letter, is read exactly as the plain spelling and refuses the set.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterReportsPrivateOrSymmetricMemberPresentForAnUpperCaseHexEscapedMemberName()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocPrivateEscapedKUpperCaseHex), WellKnownJwkValues.UseSigUtf8);

        Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, result.Outcome);
        Assert.IsNull(result.Members);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-6">RFC 7517 §6</see> adopts
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.3">RFC 7515 §5.3</see> for member
    /// VALUES too: a <c>use</c> value whose middle letter is written as a four-digit escape, its hex
    /// digit for fourteen an upper-case letter, decodes to <c>enc</c>, and the key is eligible for
    /// that filter.
    /// </summary>
    [TestMethod]
    public void SelectSoleKeyWithUseFilterSelectsWhenTheUseValueIsAnUpperCaseHexEscape()
    {
        JwkSelectionResult result = JwkJsonReader.SelectSoleKey(Utf8(DocUseEncEscapedWithUpperCaseHex), Utf8("enc"));

        Assert.AreEqual(JwkSelectionOutcome.Selected, result.Outcome);
    }


    /// <summary>
    /// Closes the class against catalog drift: for EVERY member name
    /// <see cref="WellKnownJwkMemberNames.PrivateAndSymmetricMembers"/> lists, a set holding one
    /// element that carries that member is refused by both filtered overloads — this library's own
    /// policy for a JWK Set of verification keys, not a requirement of any RFC.
    /// </summary>
    [TestMethod]
    public void EveryCatalogedPrivateOrSymmetricMemberRefusesBothFilteredOverloads()
    {
        foreach(string memberName in WellKnownJwkMemberNames.PrivateAndSymmetricMembers)
        {
            string json = $$"""{"keys":[{"kty":"EC","kid":"k","use":"sig","{{memberName}}":"secret"}]}""";

            JwkSelectionResult byKeyId = JwkJsonReader.SelectKeyByKeyId(Utf8(json), "k", WellKnownJwkValues.UseSigUtf8);
            JwkSelectionResult soleKey = JwkJsonReader.SelectSoleKey(Utf8(json), WellKnownJwkValues.UseSigUtf8);

            Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, byKeyId.Outcome, $"kid mode, member '{memberName}'");
            Assert.AreEqual(JwkSelectionOutcome.PrivateOrSymmetricMemberPresent, soleKey.Outcome, $"sole-key mode, member '{memberName}'");
        }
    }
}
