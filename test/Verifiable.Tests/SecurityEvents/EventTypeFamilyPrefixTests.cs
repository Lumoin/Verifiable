using System.Reflection;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// The event-type classes declare each member's full URI as its own UTF-8 source literal
/// while the family-membership predicates (<c>Is*EventType</c>) match on a shared prefix
/// constant. This sweep pins the two in coherence: every declared event-type URI must
/// satisfy its family predicate, so a typo in either a member literal or the prefix is
/// caught structurally rather than by a downstream interop failure.
/// </summary>
[TestClass]
internal sealed class EventTypeFamilyPrefixTests
{
    [TestMethod]
    public void EveryEventTypeUriCarriesItsFamilyPrefix()
    {
        AssertFamily(typeof(CaepEventTypes), CaepEventTypes.IsCaepEventType, expectedMemberCount: 8);
        AssertFamily(typeof(RiscEventTypes), RiscEventTypes.IsRiscEventType, expectedMemberCount: 14);
        AssertFamily(typeof(SsfEventTypes), SsfEventTypes.IsSsfEventType, expectedMemberCount: 2);
    }


    private static void AssertFamily(Type type, Func<string, bool> isFamilyMember, int expectedMemberCount)
    {
        FieldInfo[] members = [.. type
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(static field => field.FieldType == typeof(string))];

        Assert.HasCount(expectedMemberCount, members,
            $"{type.Name} must declare its spec catalogue of event-type URIs.");
        foreach(FieldInfo member in members)
        {
            string uri = (string)member.GetValue(null)!;
            Assert.IsTrue(isFamilyMember(uri),
                $"{type.Name}.{member.Name} (\"{uri}\") must carry its family's prefix.");
        }
    }
}
