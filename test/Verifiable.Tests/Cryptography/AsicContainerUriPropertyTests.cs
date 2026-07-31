using System;
using System.Globalization;
using System.Text;
using CsCheck;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="AsicContainerUri"/>, the one place Annex A.6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> lives.
/// </summary>
/// <remarks>
/// The resolver fails silently when it is wrong: a reference resolved against the wrong base, or an escape
/// decoded differently on the two sides, names a different entry with no structural error anywhere, and the
/// only symptom is a digest that does not match. That is the shape a property test catches and an example
/// does not. A failing sample is a defect, not noise: CsCheck shrinks it and prints the seed that reproduces
/// it.
/// </remarks>
[TestClass]
internal sealed class AsicContainerUriPropertyTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The entry-name octet bound every sample is validated under, matching the container reader's own.</summary>
    private static int NameBound { get; } = 512;

    /// <summary>
    /// The characters entry-name segments are generated from: unreserved ones, ones a URI reserves as
    /// delimiters, ones only a percent encoding can carry, and non-ASCII ones whose UTF-8 octets have to
    /// survive the round trip.
    /// </summary>
    private static string SegmentAlphabet { get; } = "abzAZ09-._~ +%?#&=@!$'()*,;:[]<>\"\\{}|^`\u00e4\u00df\u4e2d";

    /// <summary>The prefixes the refusal property prepends to an otherwise well-formed reference.</summary>
    private static string[] HostilePrefixes { get; } = ["", "/", "//", "../", "./", "http://host/", "\\", "%2E%2E/", "%2F", "%"];

    /// <summary>Generates one path segment of one to eight characters drawn from <see cref="SegmentAlphabet"/>.</summary>
    private static Gen<string> GenSegment { get; } =
        Gen.Int[0, SegmentAlphabet.Length - 1].Array[1, 8].Select(indices =>
        {
            var characters = new char[indices.Length];
            for(int i = 0; i < indices.Length; ++i)
            {
                characters[i] = SegmentAlphabet[indices[i]];
            }

            return new string(characters);
        });

    /// <summary>Generates a container entry name of one to four segments.</summary>
    private static Gen<string> GenEntryName { get; } =
        GenSegment.Array[1, 4].Select(segments => string.Join('/', segments));


    /// <summary>
    /// Writing a reference for an entry name and resolving it again returns exactly that name, for every name
    /// the container layer admits — which is what makes a manifest this library writes readable by the same
    /// rules it reads other producers' manifests with.
    /// </summary>
    [TestMethod]
    public void WritingAReferenceAndResolvingItAgainReturnsTheSameEntryName()
    {
        GenEntryName.Sample(entryName =>
        {
            //The alphabet is wide enough to produce names no container carries (a backslash, a colon, a
            //traversal segment). Those are the refusal property's business, and ToReference refuses them by
            //contract rather than writing a reference for them.
            if(AsicZipEntryNaming.Validate(entryName, NameBound) != AsicZipEntryNameStatus.Accepted)
            {
                return true;
            }

            string reference = AsicContainerUri.ToReference(entryName);
            AsicContainerUriResolution resolution = AsicContainerUri.Resolve(reference);

            return resolution.IsResolved && string.Equals(resolution.EntryName, entryName, StringComparison.Ordinal);
        });
    }


    /// <summary>
    /// A written reference carries no character outside the unreserved set of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">IETF RFC 3986 clause 2.3</see>, the
    /// percent sign, the hexadecimal digits and the path separator — so no reference this library writes can
    /// carry a delimiter whose meaning a consumer would have to decide.
    /// </summary>
    [TestMethod]
    public void AWrittenReferenceCarriesNothingButUnreservedCharactersEscapesAndSeparators()
    {
        GenEntryName.Sample(entryName =>
        {
            if(AsicZipEntryNaming.Validate(entryName, NameBound) != AsicZipEntryNameStatus.Accepted)
            {
                return true;
            }

            foreach(char character in AsicContainerUri.ToReference(entryName))
            {
                bool admitted = char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' or '~' or '%' or '/';
                if(!admitted)
                {
                    return false;
                }
            }

            return true;
        });
    }


    /// <summary>
    /// No reference ever resolves to a name the container layer would refuse to carry: whatever a producer
    /// writes, what comes out is either a refusal owning no name at all or a name that has already passed
    /// <see cref="AsicZipEntryNaming.Validate"/>. This is Annex A.6 item 3 stated as an invariant rather than
    /// as a list of cases.
    /// </summary>
    [TestMethod]
    public void NoReferenceEverResolvesToANameTheContainerLayerWouldRefuse()
    {
        (from prefixIndex in Gen.Int[0, HostilePrefixes.Length - 1]
         from segments in GenSegment.Array[1, 4]
         select HostilePrefixes[prefixIndex] + string.Join('/', segments))
        .Sample(reference =>
        {
            AsicContainerUriResolution resolution = AsicContainerUri.Resolve(reference);

            return resolution.IsResolved
                ? AsicZipEntryNaming.Validate(resolution.EntryName, NameBound) == AsicZipEntryNameStatus.Accepted
                : resolution.EntryName is null;
        });
    }


    /// <summary>
    /// Resolution depends on the octets a reference names and not on how they were spelled: a name written
    /// with as few escapes as the format allows resolves to the same entry as the same name with every octet
    /// escaped, which is a spelling a producer may legitimately write and this library never does.
    /// </summary>
    [TestMethod]
    public void TwoSpellingsOfTheSameReferenceResolveToTheSameEntry()
    {
        GenEntryName.Sample(entryName =>
        {
            if(AsicZipEntryNaming.Validate(entryName, NameBound) != AsicZipEntryNameStatus.Accepted)
            {
                return true;
            }

            AsicContainerUriResolution fromWritten = AsicContainerUri.Resolve(AsicContainerUri.ToReference(entryName));
            AsicContainerUriResolution fromFullyEscaped = AsicContainerUri.Resolve(EscapeEveryOctet(entryName));

            return fromWritten.IsResolved
                && fromFullyEscaped.IsResolved
                && string.Equals(fromWritten.EntryName, fromFullyEscaped.EntryName, StringComparison.Ordinal);
        });

        //Writes the maximally escaped spelling of an entry name, leaving only the path separator as itself.
        static string EscapeEveryOctet(string entryName)
        {
            var builder = new StringBuilder();
            foreach(byte octet in Encoding.UTF8.GetBytes(entryName))
            {
                _ = octet == (byte)'/'
                    ? builder.Append('/')
                    : builder.Append('%').Append(octet.ToString("X2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }
}
