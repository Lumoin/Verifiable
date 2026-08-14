using System;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the JAdES clause 5.4 shared-syntax types — <c>oId</c> (<see cref="AdESObjectIdentifier"/>),
/// <c>pkiOb</c> (<see cref="AdESPkiObject"/>), and <c>tstContainer</c>/<c>tstToken</c>
/// (<see cref="AdESTimestampContainer"/>/<see cref="AdESTimestampToken"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.4.
/// </summary>
/// <remarks>
/// These MODELS are serialization-free — the JSON encoding
/// delegates are a separate concern. This suite exercises construction, validation (the schema's
/// <c>minItems: 1</c> cardinality constraints, enforced at the model constructor since no parse layer exists
/// yet to enforce it), and byte-exact carriage of the members that hold raw bytes.
/// </remarks>
[TestClass]
internal sealed class JAdESSharedSyntaxTests
{
    /// <summary>Constructing with only the required <c>id</c> member leaves <c>desc</c>/<c>docRefs</c> null.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.1-01, JA-5.4.1-07.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierConstructsWithIdOnly()
    {
        const string id = "https://example.org/jades/oid/1";

        var model = new AdESObjectIdentifier(id);

        Assert.AreEqual(id, model.Id);
        Assert.IsNull(model.Desc);
        Assert.IsNull(model.DocRefs);
    }


    /// <summary>Constructing with <c>id</c> and <c>desc</c> carries both through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.1-02, JA-5.4.1-10.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierConstructsWithIdAndDesc()
    {
        const string id = "https://example.org/jades/oid/2";
        const string desc = "A short informal description of the identified object.";

        var model = new AdESObjectIdentifier(id, desc);

        Assert.AreEqual(id, model.Id);
        Assert.AreEqual(desc, model.Desc);
        Assert.IsNull(model.DocRefs);
    }


    /// <summary>Constructing with <c>id</c> and a non-empty <c>docRefs</c> array carries every entry in order.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.1-03, JA-5.4.1-11.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierConstructsWithIdAndDocRefs()
    {
        const string id = "https://example.org/jades/oid/3";
        Uri[] docRefs = [new Uri("https://example.org/docs/spec-1"), new Uri("https://example.org/docs/spec-2")];

        var model = new AdESObjectIdentifier(id, docRefs: docRefs);

        Assert.AreEqual(id, model.Id);
        Assert.IsNull(model.Desc);
        Assert.IsNotNull(model.DocRefs);
        Assert.HasCount(docRefs.Length, model.DocRefs!);
        for(int i = 0; i < docRefs.Length; i++)
        {
            Assert.AreEqual(docRefs[i], model.DocRefs![i], $"docRefs[{i}] must carry through unchanged.");
        }
    }


    /// <summary>Constructing with every member (<c>id</c>, <c>desc</c>, <c>docRefs</c>) carries all three.</summary>
    [TestMethod]
    public void ObjectIdentifierConstructsWithAllMembers()
    {
        const string id = "https://example.org/jades/oid/4";
        const string desc = "Technical specification defining the signature policy document syntax.";
        Uri[] docRefs = [new Uri("https://example.org/docs/spec-1")];

        var model = new AdESObjectIdentifier(id, desc, docRefs);

        Assert.AreEqual(id, model.Id);
        Assert.AreEqual(desc, model.Desc);
        Assert.IsNotNull(model.DocRefs);
        Assert.HasCount(1, model.DocRefs!);
        Assert.AreEqual(docRefs[0], model.DocRefs![0]);
    }


    /// <summary>A <see langword="null"/> <c>id</c> must fail closed — <c>id</c> is required (JA-5.4.1-05).</summary>
    [TestMethod]
    public void ConstructingObjectIdentifierWithNullIdThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESObjectIdentifier(null!));
    }


    /// <summary>An empty <c>id</c> must fail closed — exact-character-sequence carriage means an empty string is never a valid identifier.</summary>
    [TestMethod]
    public void ConstructingObjectIdentifierWithEmptyIdThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new AdESObjectIdentifier(string.Empty));
    }


    /// <summary>
    /// The schema's <c>minItems: 1</c> constraint (clause 5.4.1) requires a present <c>docRefs</c> member to be
    /// non-empty; constructing with an empty <c>docRefs</c> array must fail closed.
    /// </summary>
    [TestMethod]
    public void ConstructingObjectIdentifierWithEmptyDocRefsArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESObjectIdentifier("https://example.org/jades/oid/1", docRefs: []));
    }


    /// <summary>The required <c>val</c> member carries the exact bytes supplied — a borrowed view, not a copy.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.2-01, JA-5.4.2-03.
    /// </remarks>
    [TestMethod]
    public void PkiObjectCarriesValBytesUnchanged()
    {
        byte[] val = [0x30, 0x82, 0x01, 0x0A]; // A plausible DER SEQUENCE prefix; opaque to this type either way.

        var model = new AdESPkiObject { Val = val };

        Assert.IsTrue(val.AsSpan().SequenceEqual(model.Val.Span), "The 'val' member must carry the supplied bytes unchanged.");
        Assert.IsNull(model.Encoding);
        Assert.IsNull(model.SpecRef);
    }


    /// <summary>The optional <c>encoding</c> member carries through when supplied.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.2-04.
    /// </remarks>
    [TestMethod]
    public void PkiObjectCarriesEncodingWhenSupplied()
    {
        byte[] val = [0x30, 0x03, 0x02, 0x01, 0x01];
        const string encoding = "http://uri.etsi.org/01903/v1.2.2#DER";

        var model = new AdESPkiObject { Val = val, Encoding = encoding };

        Assert.AreEqual(encoding, model.Encoding);
        Assert.IsNull(model.SpecRef);
    }


    /// <summary>
    /// The optional <c>specRef</c> member is a plain string — not upgraded to <see cref="Uri"/> — mirroring
    /// the Annex B.1 schema's own untyped <c>{"type": "string"}</c> for this member (contrast <c>encoding</c>,
    /// which does carry a <c>"format": "uri"</c> assertion).
    /// </summary>
    [TestMethod]
    public void PkiObjectCarriesSpecRefAsPlainString()
    {
        byte[] val = [0x04, 0x02, 0xCA, 0xFE];
        const string specRef = "not-a-uri-shaped specRef string, per the schema's own plain-string typing";

        var model = new AdESPkiObject { Val = val, SpecRef = specRef };

        Assert.AreEqual(specRef, model.SpecRef);
    }


    /// <summary>Every member (<c>val</c>, <c>encoding</c>, <c>specRef</c>) carries through when all are supplied.</summary>
    [TestMethod]
    public void PkiObjectCarriesAllMembersWhenSupplied()
    {
        byte[] val = [0x30, 0x82, 0x02, 0x00];
        const string encoding = "http://uri.etsi.org/01903/v1.2.2#DER";
        const string specRef = "https://example.org/specs/x509-attribute-certificate";

        var model = new AdESPkiObject { Val = val, Encoding = encoding, SpecRef = specRef };

        Assert.IsTrue(val.AsSpan().SequenceEqual(model.Val.Span));
        Assert.AreEqual(encoding, model.Encoding);
        Assert.AreEqual(specRef, model.SpecRef);
    }


    /// <summary>A single RFC 3161-shaped token (<c>type</c>/<c>encoding</c>/<c>specRef</c> all absent) constructs and carries its bytes.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.3.3-12.
    /// </remarks>
    [TestMethod]
    public void TimestampContainerConstructsWithRfc3161StyleToken()
    {
        byte[] tokenVal = [0x30, 0x82, 0x03, 0x00];
        var token = new AdESTimestampToken { Val = tokenVal };

        using var container = new AdESTimestampContainer([token]);

        Assert.HasCount(1, container.TstTokens);
        Assert.IsTrue(tokenVal.AsSpan().SequenceEqual(container.TstTokens[0].Val.Span));
        Assert.IsNull(container.TstTokens[0].Type);
        Assert.IsNull(container.TstTokens[0].Encoding);
        Assert.IsNull(container.TstTokens[0].SpecRef);
        Assert.IsNull(container.CanonAlg);
    }


    /// <summary>A token carrying every optional member (<c>type</c>, <c>encoding</c>, <c>specRef</c>) carries all three through.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.4.3.3-01, JA-5.4.3.3-06, JA-5.4.3.3-08, JA-5.4.3.3-10.
    /// </remarks>
    [TestMethod]
    public void TimestampContainerConstructsWithFullyPopulatedToken()
    {
        byte[] tokenVal = [0x05, 0x06, 0x07];
        var token = new AdESTimestampToken
        {
            Val = tokenVal,
            Type = "application/vnd.example.timestamp",
            Encoding = "https://example.org/encodings/example-tst",
            SpecRef = "https://example.org/specs/example-tst-format"
        };

        using var container = new AdESTimestampContainer([token]);

        AdESTimestampToken actual = container.TstTokens[0];
        Assert.IsTrue(tokenVal.AsSpan().SequenceEqual(actual.Val.Span));
        Assert.AreEqual(token.Type, actual.Type);
        Assert.AreEqual(token.Encoding, actual.Encoding);
        Assert.AreEqual(token.SpecRef, actual.SpecRef);
    }


    /// <summary>
    /// Multiple tokens of independently varying shape (JA-5.4.3.3-03: more than one token for the same
    /// message imprint, e.g. one per Time-Stamping Authority) construct and carry through in their exact
    /// supplied order.
    /// </summary>
    [TestMethod]
    public void TimestampContainerConstructsWithMultipleTokensInSuppliedOrder()
    {
        AdESTimestampToken[] tokens =
        [
            new() { Val = new byte[] { 0x10 } },
            new() { Val = new byte[] { 0x11, 0x12 }, Type = "application/vnd.example.timestamp" },
            new() { Val = new byte[] { 0x13, 0x14, 0x15 }, Encoding = "https://example.org/encodings/third-tst" }
        ];

        using var container = new AdESTimestampContainer(tokens);

        Assert.HasCount(tokens.Length, container.TstTokens);
        for(int i = 0; i < tokens.Length; i++)
        {
            Assert.IsTrue(tokens[i].Val.Span.SequenceEqual(container.TstTokens[i].Val.Span), $"tstTokens[{i}]'s 'val' member must carry through byte-for-byte.");
            Assert.AreEqual(tokens[i].Type, container.TstTokens[i].Type, $"tstTokens[{i}]'s 'type' member must carry through.");
            Assert.AreEqual(tokens[i].Encoding, container.TstTokens[i].Encoding, $"tstTokens[{i}]'s 'encoding' member must carry through.");
        }
    }


    /// <summary>
    /// A present <c>canonAlg</c> member (JA-5.4.3.3-16) carries through — the JAdES-only member absent from
    /// <see cref="AdESTimestampContainer"/>.
    /// </summary>
    [TestMethod]
    public void TimestampContainerConstructsWithCanonAlg()
    {
        const string canonAlg = "http://www.w3.org/2006/12/xml-c14n11";
        var token = new AdESTimestampToken { Val = new byte[] { 0x01 } };

        using var container = new AdESTimestampContainer([token], canonAlg);

        Assert.AreEqual(canonAlg, container.CanonAlg);
    }


    /// <summary>A <see langword="null"/> <c>tstTokens</c> argument must fail closed — <c>tstTokens</c> is required.</summary>
    [TestMethod]
    public void ConstructingTimestampContainerWithNullTokensThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new AdESTimestampContainer(null!));
    }


    /// <summary>
    /// The schema's <c>minItems: 1</c> constraint (clause 5.4.3.3, JA-5.4.3.3-05) requires <c>tstTokens</c> to
    /// be non-empty; constructing with an empty array must fail closed.
    /// </summary>
    [TestMethod]
    public void ConstructingTimestampContainerWithEmptyTokensArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESTimestampContainer(Array.Empty<AdESTimestampToken>()));
    }


    /// <summary><see cref="AdESTimestampContainer.Dispose"/> is idempotent and safe to call any number of times.</summary>
    [TestMethod]
    public void TimestampContainerDisposeIsIdempotent()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 } }]);

        container.Dispose();
        container.Dispose();
    }
}
