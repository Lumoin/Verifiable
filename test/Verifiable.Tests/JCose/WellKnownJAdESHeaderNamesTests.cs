using System.Linq;
using System.Reflection;
using Verifiable.JCose;

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
    /// <summary>One registered JAdES name under test: its declaring field, its exact wire text, the defining
    /// clause, and the <c>Is*</c> predicate that should recognize it.</summary>
    /// <param name="FieldName">The <see cref="WellKnownJAdESHeaderNames"/> field name (for reflection cross-check).</param>
    /// <param name="WireValue">The exact wire string, transcribed from the leg table.</param>
    /// <param name="Clause">The defining clause, for failure-message traceability.</param>
    /// <param name="Predicate">The registry's own <c>Is*</c> predicate for this name.</param>
    private sealed record RegisteredName(string FieldName, string WireValue, string Clause, Func<string, bool> Predicate);


    /// <summary>
    /// The fifteen names <see cref="WellKnownJAdESHeaderNames"/> registers — the nine JAdES-new header
    /// parameters, <c>sigD</c>'s five own members, and <c>etsiU</c> — in leg-table clause order.
    /// </summary>
    private static RegisteredName[] AllRegisteredNames() =>
    [
        new(nameof(WellKnownJAdESHeaderNames.SigT), "sigT", "5.2.1", WellKnownJAdESHeaderNames.IsSigT),
        new(nameof(WellKnownJAdESHeaderNames.X5tHashO), "x5t#o", "5.2.2.2", WellKnownJAdESHeaderNames.IsX5tHashO),
        new(nameof(WellKnownJAdESHeaderNames.SigX5ts), "sigX5ts", "5.2.2.3", WellKnownJAdESHeaderNames.IsSigX5ts),
        new(nameof(WellKnownJAdESHeaderNames.SrCms), "srCms", "5.2.3", WellKnownJAdESHeaderNames.IsSrCms),
        new(nameof(WellKnownJAdESHeaderNames.SigPl), "sigPl", "5.2.4", WellKnownJAdESHeaderNames.IsSigPl),
        new(nameof(WellKnownJAdESHeaderNames.SrAts), "srAts", "5.2.5", WellKnownJAdESHeaderNames.IsSrAts),
        new(nameof(WellKnownJAdESHeaderNames.AdoTst), "adoTst", "5.2.6", WellKnownJAdESHeaderNames.IsAdoTst),
        new(nameof(WellKnownJAdESHeaderNames.SigPId), "sigPId", "5.2.7.1", WellKnownJAdESHeaderNames.IsSigPId),
        new(nameof(WellKnownJAdESHeaderNames.SigD), "sigD", "5.2.8.1", WellKnownJAdESHeaderNames.IsSigD),
        new(nameof(WellKnownJAdESHeaderNames.MId), "mId", "5.2.8.1", WellKnownJAdESHeaderNames.IsMId),
        new(nameof(WellKnownJAdESHeaderNames.Pars), "pars", "5.2.8.1", WellKnownJAdESHeaderNames.IsPars),
        new(nameof(WellKnownJAdESHeaderNames.HashM), "hashM", "5.2.8.1", WellKnownJAdESHeaderNames.IsHashM),
        new(nameof(WellKnownJAdESHeaderNames.HashV), "hashV", "5.2.8.1", WellKnownJAdESHeaderNames.IsHashV),
        new(nameof(WellKnownJAdESHeaderNames.Ctys), "ctys", "5.2.8.1", WellKnownJAdESHeaderNames.IsCtys),
        new(nameof(WellKnownJAdESHeaderNames.EtsiU), "etsiU", "4/5.3.1", WellKnownJAdESHeaderNames.IsEtsiU)
    ];


    /// <summary>
    /// Reflection sweep: every <c>public static readonly string</c> field declared on
    /// <see cref="WellKnownJAdESHeaderNames"/> has exactly one row in <see cref="AllRegisteredNames"/> — the
    /// registry cannot silently grow (or shrink) a name without this test's table changing too, and the table
    /// cannot claim a row for a name the class does not actually declare.
    /// </summary>
    [TestMethod]
    public void EveryDeclaredFieldHasExactlyOneTableRowAndViceVersa()
    {
        FieldInfo[] declaredFields = [.. typeof(WellKnownJAdESHeaderNames)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(static field => field.FieldType == typeof(string))];

        RegisteredName[] rows = AllRegisteredNames();

        Assert.HasCount(rows.Length, declaredFields,
            "WellKnownJAdESHeaderNames must declare exactly the fifteen names the leg tables extract -- no more, no fewer.");

        string[] declaredNames = [.. declaredFields.Select(static f => f.Name).OrderBy(static n => n, StringComparer.Ordinal)];
        string[] tableNames = [.. rows.Select(static r => r.FieldName).OrderBy(static n => n, StringComparer.Ordinal)];

        Assert.AreSequenceEqual(tableNames, declaredNames,
            "Every declared field must have exactly one AllRegisteredNames() row, and vice versa.");
    }


    /// <summary>
    /// Every registered constant's runtime value matches the leg table's verbatim wire text exactly --
    /// a spec-fidelity pin, not a runtime-varying check.
    /// </summary>
    [TestMethod]
    public void RegisteredConstantsMatchTheLegTablesVerbatim()
    {
        foreach(RegisteredName entry in AllRegisteredNames())
        {
            FieldInfo field = typeof(WellKnownJAdESHeaderNames).GetField(entry.FieldName, BindingFlags.Public | BindingFlags.Static)!;
            string actual = (string)field.GetValue(null)!;

            Assert.AreEqual(entry.WireValue, actual,
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
    /// WellKnown classes are NOT re-declared as fields on <see cref="WellKnownJAdESHeaderNames"/>.
    /// </summary>
    [TestMethod]
    public void OverlappingNamesAreNotRedeclaredOnThisClass()
    {
        Type jadesType = typeof(WellKnownJAdESHeaderNames);

        foreach(string reusedFieldName in new[] { "Iat", "Cty", "B64", "X5t", "X5tHashS256", "X5u", "X5c", "Alg", "Kid", "Crit" })
        {
            Assert.IsNull(jadesType.GetField(reusedFieldName, BindingFlags.Public | BindingFlags.Static),
                $"WellKnownJAdESHeaderNames must not declare a duplicate field named \"{reusedFieldName}\" -- it must be reused from its owning registry.");
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

            FieldInfo field = typeof(WellKnownJAdESHeaderNames).GetField(entry.FieldName, BindingFlags.Public | BindingFlags.Static)!;
            string registryConstant = (string)field.GetValue(null)!;

            Assert.AreSame(registryConstant, canonicalized,
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
