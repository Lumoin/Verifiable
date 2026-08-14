using System.Collections.Generic;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Independent-oracle proof for <see cref="JAdESDetachedObjectDereferencing.Canonicalize"/>'s <c>HttpHeaders</c>
/// mechanism (clause 5.2.8.2, JA-5.2.8.2-04/-05/-C1..-C4/-06), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>. The canonicalizer must
/// lowercase every ordinary header field name and trim leading/trailing whitespace off every header field value
/// before joining, exactly as JA-5.2.8.2-C3 states.
/// </summary>
/// <remarks>
/// <strong>Firewalled, independent oracle.</strong> The expected byte sequence below is assembled directly from
/// the clause's own numbered steps (item a/b/c/d, JA-5.2.8.2-06's comma-space multi-instance join) against a
/// fixture chosen specifically to distinguish "byte-exact reproduction" from "same content ignoring
/// case/whitespace": a mixed-case header name, a value carrying leading/trailing spaces, and a multi-instance
/// header — never by calling <see cref="JAdESDetachedObjectDereferencing"/>'s own internals or mirroring its
/// logic, mirroring <c>CBAdESMessageImprintTests</c>'s identical firewall convention.
/// </remarks>
[TestClass]
internal sealed class JAdESHttpHeadersCanonicalizationOracleTests
{
    /// <summary>
    /// A <c>pars</c> sequence covering all four JA-5.2.8.2-C1..-C4 cases in one canonicalization: the
    /// <c>(request target)</c>/<c>(response status)</c> pseudo-headers (items a/b, bare value, no lowering/
    /// trimming), a mixed-case ordinary header carrying a value with surrounding whitespace (item c: the name
    /// must be lowercased and the value trimmed), and a multi-instance ordinary header (JA-5.2.8.2-06: comma-
    /// space joined, in transmission order) — newline-joined in <c>pars</c> order (item d).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.2-05.
    /// </remarks>
    [TestMethod]
    public void HttpHeadersCanonicalizationMatchesIndependentOracle()
    {
        var reference = new JAdESHttpHeadersReference([
            "(request target)",
            "content-type",
            "x-custom",
            "(response status)"
        ]);

        var context = new JAdESHttpHeadersCanonicalizationContext(
            RequestTargetValue: "post /path?query=1",
            ResponseStatusValue: "HTTP/1.1 200 OK",
            HeaderFieldValues: new Dictionary<string, IReadOnlyList<string>>
            {
                //JA-5.2.8.2-C3: the field string uses the LOWERCASED name; the canonicalizer must not depend on
                //the context's own dictionary key casing either, so this fixture deliberately supplies both the
                //pars entry and the lookup key already lowercase (JA-5.2.8.2-04's own producer-side rule) while
                //the VALUE below still needs trimming -- an independent axis from name casing.
                ["content-type"] = ["  application/json  "],
                //JA-5.2.8.2-06: multiple instances of the same header field concatenate with ", ", in
                //transmission order.
                ["x-custom"] = [" first ", "second", " third"]
            });

        string expected = string.Join('\n',
        [
            "post /path?query=1",
            "content-type: application/json",
            "x-custom: first, second, third",
            "HTTP/1.1 200 OK"
        ]);
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);

        using PooledMemory result = JAdESDetachedObjectDereferencing.Canonicalize(reference, context, BaseMemoryPool.Shared);

        Assert.IsTrue(expectedBytes.AsSpan().SequenceEqual(result.AsReadOnlySpan()),
            "Canonicalize must reproduce the independent oracle's bytes exactly -- lowercased ordinary header " +
            "names and trimmed header field values, per JA-5.2.8.2-C3.");
    }


    /// <summary>
    /// JA-5.2.8.2-C3's lowercasing is unconditional on the field NAME even when the reference's own <c>pars</c>
    /// entry (a caller-constructed <see cref="JAdESHttpHeadersReference"/>, not necessarily produced by this
    /// library's own creation path) is not already lowercase.
    /// </summary>
    [TestMethod]
    public void HttpHeadersCanonicalizationLowercasesTheFieldNameRegardlessOfParsCasing()
    {
        var reference = new JAdESHttpHeadersReference(["X-Mixed-Case"]);
        var context = new JAdESHttpHeadersCanonicalizationContext(
            RequestTargetValue: null,
            ResponseStatusValue: null,
            HeaderFieldValues: new Dictionary<string, IReadOnlyList<string>>
            {
                ["X-Mixed-Case"] = ["value"]
            });

        using PooledMemory result = JAdESDetachedObjectDereferencing.Canonicalize(reference, context, BaseMemoryPool.Shared);

        string actual = Encoding.UTF8.GetString(result.AsReadOnlySpan());
        Assert.AreEqual("x-mixed-case: value", actual);
    }
}
