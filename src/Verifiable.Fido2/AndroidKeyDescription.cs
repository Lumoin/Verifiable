using System.Diagnostics;
using System.Formats.Asn1;

namespace Verifiable.Fido2;

/// <summary>
/// The subset of a decoded <c>AuthorizationList</c> (either the key description's
/// <c>softwareEnforced</c> or <c>teeEnforced</c> list) that
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web
/// Authentication Level 3, section 8.4: Android Key Attestation Statement Format</see>'s
/// verification procedure inspects.
/// </summary>
/// <param name="Purposes">
/// The decoded values of the authorization list's <c>purpose</c> field (a SET OF INTEGER), or an
/// empty set when the field is absent.
/// </param>
/// <param name="Origin">
/// The decoded value of the authorization list's <c>origin</c> field, or <see langword="null"/>
/// when the field is absent.
/// </param>
/// <param name="HasAllApplications">
/// <see langword="true"/> when the authorization list carries an <c>allApplications</c> field,
/// regardless of that field's own (empty, presence-only) content — section 8.4's verification
/// procedure only ever checks for this field's absence, never inspects a value inside it.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">W3C Web
/// Authentication Level 3, section 8.4.1: Android Key Attestation Statement Certificate
/// Requirements</see> names the <c>AuthorizationList.allApplications</c>,
/// <c>AuthorizationList.origin</c>, and <c>AuthorizationList.purpose</c> fields but delegates the
/// full authorization list schema to the key description schema the specification references; this
/// type carries only the three fields section 8.4's own verification procedure names.
/// </remarks>
[DebuggerDisplay("AndroidKeyAuthorizationList(Purposes={Purposes.Count}, Origin={Origin}, HasAllApplications={HasAllApplications})")]
public sealed record AndroidKeyAuthorizationList(IReadOnlySet<int> Purposes, int? Origin, bool HasAllApplications)
{
    /// <summary>
    /// Determines whether this authorization list and <paramref name="other"/> report the same
    /// <see cref="Origin"/>, <see cref="HasAllApplications"/>, and purpose set. The
    /// compiler-synthesized record equality would compare <see cref="Purposes"/> by reference,
    /// which would report two independently-parsed lists carrying the same purpose values as
    /// unequal; this override compares <see cref="Purposes"/> by set content instead.
    /// </summary>
    /// <param name="other">The other authorization list to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="Origin"/> and <see cref="HasAllApplications"/> match
    /// and <see cref="Purposes"/> is set-equal; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals(AndroidKeyAuthorizationList? other) =>
        other is not null
        && Origin == other.Origin
        && HasAllApplications == other.HasAllApplications
        && Purposes.SetEquals(other.Purposes);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(AndroidKeyAuthorizationList?)"/> —
    /// combining <see cref="Origin"/> and <see cref="HasAllApplications"/> with an
    /// order-independent combination of <see cref="Purposes"/>'s members — so two value-equal
    /// instances never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        int purposesHash = 0;
        foreach(int purpose in Purposes)
        {
            //XOR combines the set's members order-independently, matching SetEquals' own
            //order-independent equality.
            purposesHash ^= purpose.GetHashCode();
        }

        return HashCode.Combine(Origin, HasAllApplications, purposesHash);
    }
}


/// <summary>
/// The minimal parsed view of an android-key attestation certificate's key description extension
/// (OID <c>1.3.6.1.4.1.11129.2.1.17</c>) — the <c>attestationChallenge</c> and the two
/// <c>AuthorizationList</c>s
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">section 8.4</see>'s
/// verification procedure inspects.
/// </summary>
/// <param name="AttestationChallenge">
/// The key description's <c>attestationChallenge</c> OCTET STRING field, compared against
/// <c>clientDataHash</c> by section 8.4's verification procedure.
/// </param>
/// <param name="SoftwareEnforced">The key description's <c>softwareEnforced</c> authorization list.</param>
/// <param name="TeeEnforced">The key description's <c>teeEnforced</c> authorization list.</param>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements">Section 8.4.1</see>
/// states only the extension's OID and that "its schema is defined in" material the specification
/// references informatively, without reproducing the ASN.1 module inline the way section 8.4's own
/// CBOR syntax is reproduced. <see cref="Read"/> parses only the positional, top-level
/// <c>KeyDescription</c> SEQUENCE shape and the three <c>AuthorizationList</c> fields section 8.4's
/// own verification procedure names — <c>attestationVersion</c>, <c>attestationSecurityLevel</c>,
/// <c>keymasterVersion</c>, and <c>keymasterSecurityLevel</c> are skipped generically by position,
/// never interpreted.
/// </para>
/// </remarks>
[DebuggerDisplay("AndroidKeyDescription(AttestationChallenge={AttestationChallenge.Length} bytes, SoftwareEnforced={SoftwareEnforced}, TeeEnforced={TeeEnforced})")]
public sealed record AndroidKeyDescription(ReadOnlyMemory<byte> AttestationChallenge, AndroidKeyAuthorizationList SoftwareEnforced, AndroidKeyAuthorizationList TeeEnforced)
{
    /// <summary>
    /// Determines whether this key description and <paramref name="other"/> report the same content.
    /// The compiler-synthesized record equality would compare <see cref="AttestationChallenge"/> by
    /// reference/identity, which would report two independently-parsed key descriptions carrying the
    /// same challenge bytes as unequal; this override compares it by content instead.
    /// <see cref="SoftwareEnforced"/> and <see cref="TeeEnforced"/> already compare by content via
    /// <see cref="AndroidKeyAuthorizationList"/>'s own override.
    /// </summary>
    /// <param name="other">The other key description to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="AttestationChallenge"/> matches byte-for-byte and
    /// <see cref="SoftwareEnforced"/>/<see cref="TeeEnforced"/> both compare equal; otherwise
    /// <see langword="false"/>.
    /// </returns>
    public bool Equals(AndroidKeyDescription? other) =>
        other is not null
        && AttestationChallenge.Span.SequenceEqual(other.AttestationChallenge.Span)
        && SoftwareEnforced.Equals(other.SoftwareEnforced)
        && TeeEnforced.Equals(other.TeeEnforced);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(AndroidKeyDescription?)"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.AddBytes(AttestationChallenge.Span);
        hash.Add(SoftwareEnforced);
        hash.Add(TeeEnforced);

        return hash.ToHashCode();
    }


    /// <summary>
    /// The context-specific tag number of an <c>AuthorizationList</c>'s <c>purpose</c> field — a
    /// SET OF INTEGER under explicit tagging. Confirmed byte-for-byte against
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-android-key-es256">W3C Web
    /// Authentication Level 3, section 16.14: Android Key Attestation with ES256 Credential</see>'s
    /// own key description bytes, per the key description schema section 8.4.1 references.
    /// </summary>
    private const int PurposeTag = 1;

    /// <summary>
    /// The context-specific, high-tag-number-form tag number of an <c>AuthorizationList</c>'s
    /// <c>allApplications</c> field — a presence-only NULL under explicit tagging, per the key
    /// description schema section 8.4.1 references.
    /// </summary>
    private const int AllApplicationsTag = 600;

    /// <summary>
    /// The context-specific, high-tag-number-form tag number of an <c>AuthorizationList</c>'s
    /// <c>origin</c> field — an INTEGER under explicit tagging. Confirmed byte-for-byte against
    /// section 16.14's own key description bytes, per the key description schema section 8.4.1
    /// references.
    /// </summary>
    private const int OriginTag = 702;

    /// <summary>The number of leading, positionally-skipped fields preceding <c>attestationChallenge</c>.</summary>
    private const int LeadingSkippedFieldCount = 4;


    /// <summary>
    /// Parses <paramref name="extensionValue"/> — the android key attestation certificate extension's
    /// value, exactly as a <c>ReadCertificateExtensionValueDelegate</c> implementation returns it (the
    /// mandatory RFC 5280 §4.2 <c>extnValue</c> OCTET STRING wrapper already stripped, no further
    /// unwrap needed here — unlike the packed attestation AAGUID extension, whose semantic value is
    /// itself an additional OCTET STRING) — into an <see cref="AndroidKeyDescription"/>.
    /// </summary>
    /// <param name="extensionValue">The extension's raw DER (or, per <paramref name="extensionValue"/>'s producer, BER) contents.</param>
    /// <returns>The parsed key description.</returns>
    /// <remarks>
    /// Reads with <see cref="AsnEncodingRules.BER"/>, not <see cref="AsnEncodingRules.DER"/>: section
    /// 16.14's own test vector happens to use definite-length DER, but the key description schema the
    /// specification references is produced by a variety of platform encoders this layer has no
    /// control over, so the more permissive BER rule set is used to decode the structure while every
    /// comparison this type's consumer performs remains content-based, never encoding-based. The walk
    /// is iterative (no recursion): the top-level <c>KeyDescription</c> fields are read one after
    /// another by position, and each <c>AuthorizationList</c>'s tagged, OPTIONAL elements are read in
    /// a single bounded loop that skips any tag beyond <see cref="PurposeTag"/>,
    /// <see cref="AllApplicationsTag"/>, and <see cref="OriginTag"/> by its own encoded length,
    /// without ever descending into it.
    /// </remarks>
    /// <exception cref="Fido2FormatException">
    /// Thrown when <paramref name="extensionValue"/> is not a well-formed key description conforming
    /// to the positional <c>KeyDescription</c>/<c>AuthorizationList</c> shape this type parses.
    /// </exception>
    public static AndroidKeyDescription Read(ReadOnlyMemory<byte> extensionValue)
    {
        try
        {
            var reader = new AsnReader(extensionValue, AsnEncodingRules.BER);
            AsnReader keyDescriptionReader = reader.ReadSequence();
            if(reader.HasData)
            {
                throw new Fido2FormatException("The key description extension carries trailing bytes beyond its single top-level SEQUENCE.");
            }

            //attestationVersion, attestationSecurityLevel, keymasterVersion/keyMintVersion, and
            //keymasterSecurityLevel: read generically by position, per the positional decode section
            //16.14's own vector confirms — none of these four fields are inspected by section 8.4's
            //verification procedure.
            for(int skippedFieldIndex = 0; skippedFieldIndex < LeadingSkippedFieldCount; skippedFieldIndex++)
            {
                keyDescriptionReader.ReadEncodedValue();
            }

            byte[] attestationChallenge = keyDescriptionReader.ReadOctetString();

            //uniqueId: read generically by position — not inspected by section 8.4's verification procedure.
            keyDescriptionReader.ReadEncodedValue();

            AndroidKeyAuthorizationList softwareEnforced = ReadAuthorizationList(keyDescriptionReader.ReadSequence());
            AndroidKeyAuthorizationList teeEnforced = ReadAuthorizationList(keyDescriptionReader.ReadSequence());

            if(keyDescriptionReader.HasData)
            {
                throw new Fido2FormatException("The key description SEQUENCE carries a field beyond the expected eight positional fields.");
            }

            return new AndroidKeyDescription(attestationChallenge, softwareEnforced, teeEnforced);
        }
        catch(Exception exception) when(exception is AsnContentException or OverflowException)
        {
            throw new Fido2FormatException("The android key attestation certificate extension value is not a well-formed key description per the schema the specification references.", exception);
        }

        //Iteratively walks one AuthorizationList SEQUENCE's tagged, OPTIONAL elements (no recursion),
        //extracting the three fields section 8.4's verification procedure inspects and skipping every
        //other (unrecognised) context-specific tag, or any non-context-specific tag, safely by its
        //own encoded length.
        static AndroidKeyAuthorizationList ReadAuthorizationList(AsnReader listReader)
        {
            var purposes = new HashSet<int>();
            int? origin = null;
            bool hasAllApplications = false;

            while(listReader.HasData)
            {
                Asn1Tag tag = listReader.PeekTag();
                _ = (tag.TagClass, tag.TagValue) switch
                {
                    (TagClass.ContextSpecific, PurposeTag) => ReadPurposes(listReader, tag, purposes),
                    (TagClass.ContextSpecific, OriginTag) => AssignOrigin(listReader, tag, ref origin),
                    (TagClass.ContextSpecific, AllApplicationsTag) => AssignAllApplications(listReader, ref hasAllApplications),
                    _ => SkipField(listReader)
                };
            }

            return new AndroidKeyAuthorizationList(purposes, origin, hasAllApplications);

            //Reads the purpose field's SET OF INTEGER under explicit tagging into purposes.
            static bool ReadPurposes(AsnReader listReader, Asn1Tag tag, HashSet<int> purposes)
            {
                AsnReader purposeExplicit = listReader.ReadSequence(tag);
                AsnReader purposeSet = purposeExplicit.ReadSetOf(skipSortOrderValidation: true);
                while(purposeSet.HasData)
                {
                    purposes.Add(checked((int)purposeSet.ReadInteger()));
                }

                return true;
            }

            //Assigns the origin field's INTEGER under explicit tagging to origin.
            static bool AssignOrigin(AsnReader listReader, Asn1Tag tag, ref int? origin)
            {
                AsnReader originExplicit = listReader.ReadSequence(tag);
                origin = checked((int)originExplicit.ReadInteger());

                return true;
            }

            //Records allApplications' presence and skips its (empty, presence-only) content —
            //section 8.4's verification procedure never inspects a value inside allApplications,
            //only whether the field is present at all.
            static bool AssignAllApplications(AsnReader listReader, ref bool hasAllApplications)
            {
                listReader.ReadEncodedValue();
                hasAllApplications = true;

                return true;
            }

            //Skips an authorization list field this layer does not name — the key description
            //schema the specification references defines many more — by its own encoded length,
            //never interpreted.
            static bool SkipField(AsnReader listReader)
            {
                listReader.ReadEncodedValue();

                return true;
            }
        }
    }
}
