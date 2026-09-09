using System;
using System.IO;
using System.Text.RegularExpressions;
using Verifiable.JCose;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the JAdES header-parameter vocabulary registry <see cref="WellKnownJAdESHeaderNames"/> —
/// the wire NAMES clause 5.2 (plus <c>etsiU</c>, clause 4/5.3.1) newly defines, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
[TestClass]
internal sealed class WellKnownJAdESHeaderNamesTests
{
    /// <summary>The repository-relative path declaring <see cref="WellKnownJAdESHeaderNames"/>.</summary>
    private const string WellKnownJAdESHeaderNamesPath = "src/Verifiable.JCose/WellKnownJAdESHeaderNames.cs";


    /// <summary>One registered JAdES name under test: its declaring field, its exact wire text, the defining
    /// clause, and the <c>Is*</c> predicate that should recognize it.</summary>
    /// <param name="FieldName">The <see cref="WellKnownJAdESHeaderNames"/> field name, for messages only.</param>
    /// <param name="TabledValue">The registry's own interned constant for this field, read directly rather than by name.</param>
    /// <param name="WireValue">The exact wire string, transcribed from the spec's own clause.</param>
    /// <param name="Clause">The defining clause, for failure-message traceability.</param>
    /// <param name="Predicate">The registry's own <c>Is*</c> predicate for this name.</param>
    private sealed record RegisteredName(string FieldName, string TabledValue, string WireValue, string Clause, Func<string, bool> Predicate);


    /// <summary>
    /// The fifteen names <see cref="WellKnownJAdESHeaderNames"/> registers — the nine JAdES-new header
    /// parameters, <c>sigD</c>'s five own members, and <c>etsiU</c> — in clause order.
    /// </summary>
    private static RegisteredName[] AllRegisteredNames() =>
    [
        new(nameof(WellKnownJAdESHeaderNames.SigT), WellKnownJAdESHeaderNames.SigT, "sigT", "5.2.1", WellKnownJAdESHeaderNames.IsSigT),
        new(nameof(WellKnownJAdESHeaderNames.X5tHashO), WellKnownJAdESHeaderNames.X5tHashO, "x5t#o", "5.2.2.2", WellKnownJAdESHeaderNames.IsX5tHashO),
        new(nameof(WellKnownJAdESHeaderNames.SigX5ts), WellKnownJAdESHeaderNames.SigX5ts, "sigX5ts", "5.2.2.3", WellKnownJAdESHeaderNames.IsSigX5ts),
        new(nameof(WellKnownJAdESHeaderNames.SrCms), WellKnownJAdESHeaderNames.SrCms, "srCms", "5.2.3", WellKnownJAdESHeaderNames.IsSrCms),
        new(nameof(WellKnownJAdESHeaderNames.SigPl), WellKnownJAdESHeaderNames.SigPl, "sigPl", "5.2.4", WellKnownJAdESHeaderNames.IsSigPl),
        new(nameof(WellKnownJAdESHeaderNames.SrAts), WellKnownJAdESHeaderNames.SrAts, "srAts", "5.2.5", WellKnownJAdESHeaderNames.IsSrAts),
        new(nameof(WellKnownJAdESHeaderNames.AdoTst), WellKnownJAdESHeaderNames.AdoTst, "adoTst", "5.2.6", WellKnownJAdESHeaderNames.IsAdoTst),
        new(nameof(WellKnownJAdESHeaderNames.SigPId), WellKnownJAdESHeaderNames.SigPId, "sigPId", "5.2.7.1", WellKnownJAdESHeaderNames.IsSigPId),
        new(nameof(WellKnownJAdESHeaderNames.SigD), WellKnownJAdESHeaderNames.SigD, "sigD", "5.2.8.1", WellKnownJAdESHeaderNames.IsSigD),
        new(nameof(WellKnownJAdESHeaderNames.MId), WellKnownJAdESHeaderNames.MId, "mId", "5.2.8.1", WellKnownJAdESHeaderNames.IsMId),
        new(nameof(WellKnownJAdESHeaderNames.Pars), WellKnownJAdESHeaderNames.Pars, "pars", "5.2.8.1", WellKnownJAdESHeaderNames.IsPars),
        new(nameof(WellKnownJAdESHeaderNames.HashM), WellKnownJAdESHeaderNames.HashM, "hashM", "5.2.8.1", WellKnownJAdESHeaderNames.IsHashM),
        new(nameof(WellKnownJAdESHeaderNames.HashV), WellKnownJAdESHeaderNames.HashV, "hashV", "5.2.8.1", WellKnownJAdESHeaderNames.IsHashV),
        new(nameof(WellKnownJAdESHeaderNames.Ctys), WellKnownJAdESHeaderNames.Ctys, "ctys", "5.2.8.1", WellKnownJAdESHeaderNames.IsCtys),
        new(nameof(WellKnownJAdESHeaderNames.EtsiU), WellKnownJAdESHeaderNames.EtsiU, "etsiU", "4/5.3.1", WellKnownJAdESHeaderNames.IsEtsiU)
    ];


    /// <summary>
    /// Every registered constant's compile-time value matches the spec's own verbatim wire text exactly --
    /// a spec-fidelity pin, not a runtime-varying check.
    /// </summary>
    [TestMethod]
    public void RegisteredConstantsMatchTheLegTablesVerbatim()
    {
        foreach(RegisteredName entry in AllRegisteredNames())
        {
            Assert.AreEqual(entry.WireValue, entry.TabledValue,
                $"{entry.FieldName} (clause {entry.Clause}) must read \"{entry.WireValue}\" verbatim.");
        }
    }


    /// <summary>Each entry's own <c>Is*</c> predicate recognizes its own wire value.</summary>
    [TestMethod]
    public void EachPredicateRecognizesItsOwnName()
    {
        foreach(RegisteredName entry in AllRegisteredNames())
        {
            Assert.IsTrue(entry.Predicate(entry.WireValue),
                $"The predicate for {entry.FieldName} (clause {entry.Clause}) must recognize \"{entry.WireValue}\".");
        }
    }


    /// <summary>
    /// Each entry's own <c>Is*</c> predicate rejects every one of the other fourteen registered names -- the
    /// fifteen entries are pairwise distinguishable, not just individually recognizable.
    /// </summary>
    [TestMethod]
    public void EachPredicateRejectsTheOtherFourteenNames()
    {
        RegisteredName[] entries = AllRegisteredNames();
        for(int i = 0; i < entries.Length; i++)
        {
            for(int j = 0; j < entries.Length; j++)
            {
                if(i == j)
                {
                    continue;
                }

                Assert.IsFalse(entries[i].Predicate(entries[j].WireValue),
                    $"The predicate for {entries[i].FieldName} must reject \"{entries[j].WireValue}\" ({entries[j].FieldName}).");
            }
        }
    }


    /// <summary><see cref="WellKnownJAdESHeaderNames.IsJAdESHeaderName"/> recognizes every one of the fifteen registered names.</summary>
    [TestMethod]
    public void IsJAdESHeaderNameReturnsTrueForEveryRegisteredName()
    {
        foreach(RegisteredName entry in AllRegisteredNames())
        {
            Assert.IsTrue(WellKnownJAdESHeaderNames.IsJAdESHeaderName(entry.WireValue),
                $"{entry.FieldName} (\"{entry.WireValue}\") must be recognized as a JAdES header name.");
        }
    }


    /// <summary>
    /// <see cref="WellKnownJAdESHeaderNames.IsJAdESHeaderName"/> rejects names outside this registry's own
    /// fifteen entries, including reused RFC 7515/7519 names that live in the other WellKnown registries
    /// (<c>iat</c>, <c>cty</c>, <c>b64</c>, <c>x5t#S256</c>) -- this registry does not re-claim them.
    /// </summary>
    [TestMethod]
    public void IsJAdESHeaderNameReturnsFalseForNamesOutsideThisRegistry()
    {
        foreach(string name in new[] { "iat", "cty", "b64", "x5t#S256", "x5t", "x5u", "x5c", "alg", "kid", "crit", "not-a-header" })
        {
            Assert.IsFalse(WellKnownJAdESHeaderNames.IsJAdESHeaderName(name),
                $"\"{name}\" must not be recognized as a JAdES-registered name -- it is reused from elsewhere or unrelated.");
        }
    }


    /// <summary>
    /// The "reuse, never duplicate" rule: names already registered by RFC 7515/7519's own
    /// WellKnown classes are NOT re-declared as members on <see cref="WellKnownJAdESHeaderNames"/>. Checked
    /// as a source scan of the declaring file's own property declaration lines, with no reflection over the
    /// loaded type.
    /// </summary>
    [TestMethod]
    public void OverlappingNamesAreNotRedeclaredOnThisClass()
    {
        string text = File.ReadAllText(Path.Combine(SourceHygieneScanner.FindRepositoryRoot(), WellKnownJAdESHeaderNamesPath));

        foreach(string reusedFieldName in new[] { "Iat", "Cty", "B64", "X5t", "X5tHashS256", "X5u", "X5c", "Alg", "Kid", "Crit" })
        {
            Assert.IsFalse(
                Regex.IsMatch(text, $@"(?m)^\s*public\s+static\s+string\s+{Regex.Escape(reusedFieldName)}\s*\{{"),
                $"WellKnownJAdESHeaderNames must not declare a duplicate member named \"{reusedFieldName}\" -- it must be reused from its owning registry.");
        }

        //The values that ARE reused resolve to the exact same interned string as their owning registry --
        //no drift between "the string JAdES's clause 5.1.11 profiles" and "the string RFC 7519 claim registry owns".
        Assert.AreEqual("iat", WellKnownJwtClaimNames.Iat);
        Assert.AreSame(WellKnownJwtClaimNames.Iat, WellKnownJwtClaimNames.GetCanonicalizedValue("iat"));
        Assert.AreEqual("cty", WellKnownJoseHeaderNames.Cty);
        Assert.AreEqual("b64", WellKnownJoseHeaderNames.B64);
        Assert.AreEqual("x5t#S256", WellKnownJwkMemberNames.X5tHashS256);
    }


    /// <summary>
    /// <see cref="WellKnownJAdESHeaderNames.GetCanonicalizedValue"/> returns the interned registry constant --
    /// by reference -- for every registered name, even when the input is an equal-but-distinct instance, and
    /// returns the original (unrecognized) string unchanged otherwise.
    /// </summary>
    [TestMethod]
    public void GetCanonicalizedValueReturnsTheInternedConstantForEveryRegisteredNameAndTheOriginalOtherwise()
    {
        foreach(RegisteredName entry in AllRegisteredNames())
        {
            string equalButDistinctInstance = new(entry.WireValue.ToCharArray());
            string canonicalized = WellKnownJAdESHeaderNames.GetCanonicalizedValue(equalButDistinctInstance);

            Assert.AreEqual(entry.WireValue, canonicalized);

            Assert.AreSame(entry.TabledValue, canonicalized,
                $"GetCanonicalizedValue must return the exact interned {entry.FieldName} instance, not merely an equal string.");
        }

        string unrecognized = "not-a-jades-header";
        Assert.AreSame(unrecognized, WellKnownJAdESHeaderNames.GetCanonicalizedValue(unrecognized));
    }


    /// <summary>
    /// <see cref="WellKnownJAdESHeaderNames.Equals(string, string)"/> is ordinal and case-sensitive per
    /// RFC 7515 -- an upper-cased spelling of a registered name is a different value, never the same header.
    /// </summary>
    [TestMethod]
    public void EqualsUsesOrdinalCaseSensitiveComparison()
    {
        string upperCased = WellKnownJAdESHeaderNames.SigD.ToUpperInvariant();

        Assert.IsFalse(WellKnownJAdESHeaderNames.Equals(WellKnownJAdESHeaderNames.SigD, upperCased));
        Assert.IsFalse(WellKnownJAdESHeaderNames.IsSigD(upperCased));
    }


    /// <summary>
    /// <see cref="WellKnownJAdESHeaderNames.Equals(string, string)"/> returns <see langword="true"/> both for
    /// reference-equal inputs and for equal-but-distinct string instances -- the two branches of its own
    /// implementation.
    /// </summary>
    [TestMethod]
    public void EqualsReturnsTrueForReferenceEqualAndValueEqualInputs()
    {
        string sigD = WellKnownJAdESHeaderNames.SigD;
        string equalButDistinctInstance = new(sigD.ToCharArray());

        Assert.IsTrue(WellKnownJAdESHeaderNames.Equals(sigD, sigD));
        Assert.IsTrue(WellKnownJAdESHeaderNames.Equals(sigD, equalButDistinctInstance));
    }
}
