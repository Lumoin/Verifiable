using System.Text;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Tests.Core;

/// <summary>
/// Pins every <see cref="WellKnownCredentialMemberNames"/> member against the exact spelling the VC
/// Data Model 2.0 text uses for it, and every UTF-8 twin against the same bytes as its string.
/// </summary>
[TestClass]
internal sealed class WellKnownCredentialMemberNamesTests
{
    /// <summary>One catalog member.</summary>
    /// <param name="MemberName">The <see cref="WellKnownCredentialMemberNames"/> member under test, for messages only.</param>
    /// <param name="TabledValue">The catalog's own interned constant for this member.</param>
    /// <param name="SpecSpelling">The exact spelling the VC Data Model 2.0 text uses for this member.</param>
    /// <param name="Utf8Twin">That member's UTF-8 source literal, materialized to an array (a <see cref="ReadOnlySpan{T}"/> cannot live in a record).</param>
    private sealed record TabledMember(string MemberName, string TabledValue, string SpecSpelling, byte[] Utf8Twin);


    /// <summary>
    /// Every member <see cref="WellKnownCredentialMemberNames"/> declares, each row's spec spelling
    /// transcribed from the section its own doc comment cites.
    /// </summary>
    /// <returns>The registered members in declaration order.</returns>
    private static TabledMember[] AllRegisteredMembers() =>
    [
        new(nameof(WellKnownCredentialMemberNames.Context), WellKnownCredentialMemberNames.Context, "@context", WellKnownCredentialMemberNames.ContextUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Id), WellKnownCredentialMemberNames.Id, "id", WellKnownCredentialMemberNames.IdUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Type), WellKnownCredentialMemberNames.Type, "type", WellKnownCredentialMemberNames.TypeUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Name), WellKnownCredentialMemberNames.Name, "name", WellKnownCredentialMemberNames.NameUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Description), WellKnownCredentialMemberNames.Description, "description", WellKnownCredentialMemberNames.DescriptionUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Issuer), WellKnownCredentialMemberNames.Issuer, "issuer", WellKnownCredentialMemberNames.IssuerUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.CredentialSubject), WellKnownCredentialMemberNames.CredentialSubject, "credentialSubject", WellKnownCredentialMemberNames.CredentialSubjectUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.ValidFrom), WellKnownCredentialMemberNames.ValidFrom, "validFrom", WellKnownCredentialMemberNames.ValidFromUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.ValidUntil), WellKnownCredentialMemberNames.ValidUntil, "validUntil", WellKnownCredentialMemberNames.ValidUntilUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.CredentialStatus), WellKnownCredentialMemberNames.CredentialStatus, "credentialStatus", WellKnownCredentialMemberNames.CredentialStatusUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.CredentialSchema), WellKnownCredentialMemberNames.CredentialSchema, "credentialSchema", WellKnownCredentialMemberNames.CredentialSchemaUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Proof), WellKnownCredentialMemberNames.Proof, "proof", WellKnownCredentialMemberNames.ProofUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.RelatedResource), WellKnownCredentialMemberNames.RelatedResource, "relatedResource", WellKnownCredentialMemberNames.RelatedResourceUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.RefreshService), WellKnownCredentialMemberNames.RefreshService, "refreshService", WellKnownCredentialMemberNames.RefreshServiceUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.TermsOfUse), WellKnownCredentialMemberNames.TermsOfUse, "termsOfUse", WellKnownCredentialMemberNames.TermsOfUseUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Evidence), WellKnownCredentialMemberNames.Evidence, "evidence", WellKnownCredentialMemberNames.EvidenceUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Holder), WellKnownCredentialMemberNames.Holder, "holder", WellKnownCredentialMemberNames.HolderUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.VerifiableCredential), WellKnownCredentialMemberNames.VerifiableCredential, "verifiableCredential", WellKnownCredentialMemberNames.VerifiableCredentialUtf8.ToArray()),
        new(nameof(WellKnownCredentialMemberNames.Image), WellKnownCredentialMemberNames.Image, "image", WellKnownCredentialMemberNames.ImageUtf8.ToArray()),
    ];


    /// <summary>
    /// Every member's interned constant matches the exact spelling
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/">VC Data Model 2.0</see> uses for it, as
    /// transcribed on <see cref="AllRegisteredMembers"/> and cited on the member's own doc comment.
    /// </summary>
    [TestMethod]
    public void EveryMemberSpellsItsSpecificationNameVerbatim()
    {
        foreach(TabledMember entry in AllRegisteredMembers())
        {
            Assert.AreEqual(entry.SpecSpelling, entry.TabledValue,
                $"{entry.MemberName} must read \"{entry.SpecSpelling}\" verbatim as the VC Data Model 2.0 text spells it.");
        }
    }


    /// <summary>
    /// Every member carries a UTF-8 twin holding the same bytes as its string, so a span reader and a
    /// string comparison name the identical member rather than drifting apart.
    /// </summary>
    [TestMethod]
    public void EveryMemberHasAUtf8TwinHoldingTheSameBytes()
    {
        foreach(TabledMember entry in AllRegisteredMembers())
        {
            Assert.AreEqual(entry.TabledValue, Encoding.UTF8.GetString(entry.Utf8Twin),
                $"{entry.MemberName}Utf8 must be the UTF-8 encoding of {entry.MemberName}.");
        }
    }


    /// <summary>The catalog's members are pairwise distinct, so no wire member is ever misrouted to another's handler.</summary>
    [TestMethod]
    public void EveryMemberIsDistinctFromEveryOtherRegisteredMember()
    {
        TabledMember[] entries = AllRegisteredMembers();
        for(int i = 0; i < entries.Length; ++i)
        {
            for(int j = i + 1; j < entries.Length; ++j)
            {
                Assert.AreNotEqual(entries[i].TabledValue, entries[j].TabledValue,
                    $"{entries[i].MemberName} and {entries[j].MemberName} must not share one wire spelling.");
            }
        }
    }
}
