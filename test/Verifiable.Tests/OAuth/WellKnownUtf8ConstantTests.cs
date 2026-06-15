using System.Reflection;
using System.Text;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Structural guard for the UTF-8-first well-known constant convention: every public static
/// <c>XUtf8</c> span property must sit beside a public static string member <c>X</c> whose
/// value is the UTF-8 decoding of the span. The convention derives the string from the span's
/// single <c>u8</c> literal, so for conforming members this holds by construction — the sweep
/// exists to catch any future member that reintroduces a second hand-written literal or an
/// orphaned <c>*Utf8</c> property, across ALL classes in the scanned assemblies without
/// per-name maintenance here.
/// </summary>
[TestClass]
internal sealed class WellKnownUtf8ConstantTests
{
    //Reflection cannot box a ReadOnlySpan<byte> return value through MethodInfo.Invoke;
    //a typed delegate reads the property instead.
    private delegate ReadOnlySpan<byte> Utf8SpanGetter();


    [TestMethod]
    public void EveryUtf8SpanPropertyMatchesItsStringMember()
    {
        Assembly[] assemblies =
        [
            typeof(Verifiable.JCose.WellKnownJwtClaimNames).Assembly,
            typeof(OAuthRequestParameterNames).Assembly,
            typeof(Verifiable.Server.Diagnostics.ServerTagNames).Assembly,
            typeof(Verifiable.Vcalm.VcalmParameterNames).Assembly,
            typeof(Verifiable.Core.SecurityEvents.SubjectIdentifierFormats).Assembly,
            typeof(Verifiable.Cryptography.RsaUtilities).Assembly
        ];

        int pairCount = 0;
        List<string> orphans = [];
        List<string> mismatches = [];
        List<string> uninterned = [];

        foreach(Assembly assembly in assemblies)
        {
            foreach(Type type in assembly.GetTypes())
            {
                foreach(PropertyInfo property in type.GetProperties(
                    BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly))
                {
                    if(property.PropertyType != typeof(ReadOnlySpan<byte>)
                        || !property.Name.EndsWith("Utf8", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    string memberName = property.Name[..^"Utf8".Length];
                    FieldInfo? stringMember = type.GetField(
                        memberName, BindingFlags.Public | BindingFlags.Static);
                    if(stringMember?.FieldType != typeof(string)
                        || stringMember.GetValue(null) is not string text)
                    {
                        orphans.Add($"{type.FullName}.{property.Name}");
                        continue;
                    }

                    Utf8SpanGetter readSpan = property.GetGetMethod()!
                        .CreateDelegate<Utf8SpanGetter>();
                    if(!readSpan().SequenceEqual(Encoding.UTF8.GetBytes(text)))
                    {
                        mismatches.Add($"{type.FullName}.{memberName} = \"{text}\"");
                    }

                    //Utf8Constants.ToInternedString interns the derived string so constants
                    //stay reference-equal to literals with the same text — the fast path
                    //the canonicalization helpers rely on.
                    if(!ReferenceEquals(text, string.IsInterned(text)))
                    {
                        uninterned.Add($"{type.FullName}.{memberName}");
                    }

                    pairCount++;
                }
            }
        }

        Assert.IsEmpty(orphans,
            $"Every *Utf8 span property must have a string sibling: {string.Join(", ", orphans)}");
        Assert.IsEmpty(mismatches,
            $"UTF-8 and string views must agree: {string.Join(", ", mismatches)}");
        Assert.IsEmpty(uninterned,
            "Every derived string view must be interned (derive through " +
            $"Utf8Constants.ToInternedString): {string.Join(", ", uninterned)}");
        Assert.IsGreaterThanOrEqualTo(900, pairCount,
            "The sweep must discover the well-known constant surface; a collapse in pair " +
            "count means the discovery convention (XUtf8 property + X string field) broke.");
    }
}
