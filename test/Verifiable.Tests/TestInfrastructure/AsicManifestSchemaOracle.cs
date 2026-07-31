using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Validates a manifest document against the authentic <c>ASiCManifest</c> schema — the attachment Annex A.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> makes normative — identified by the SHA-256 that annex states for it rather
/// than by where a copy of it happens to sit.
/// </summary>
/// <remarks>
/// <para>
/// The schema is optional local reference material under <c>tempdocs/</c>, which is not a repository asset, so
/// <see cref="TryFindAuthenticSchemaAsync"/> answers <see langword="null"/> when it is absent and the tests that
/// use it report inconclusive rather than failing for a reason that has nothing to do with what they check.
/// </para>
/// <para>
/// The XML Signature declarations the ASiC schema imports are written out here from
/// <see href="https://www.w3.org/TR/xmldsig-core1/#sec-Schema">XML Signature Appendix A</see> instead of being
/// fetched from the import's stated location: a test that reaches the network fails for reasons that have
/// nothing to do with the document under validation. <c>DigestMethod</c> and <c>DigestValue</c> are declared as
/// XML Signature clauses 4.4.3.5 and 4.4.4 state them, because those two are what a manifest carries;
/// <c>Signature</c> is declared as lax content because the schema's <c>XAdESSignatures</c> element (Annex A.5,
/// XAdES-only, out of this wave's scope) reaches it and the schema set does not compile without it.
/// </para>
/// </remarks>
internal static class AsicManifestSchemaOracle
{
    /// <summary>The SHA-256 Annex A.3 states for the schema attachment, which identifies the authentic schema wherever a copy of it sits.</summary>
    internal static string AuthenticSchemaDigest { get; } = "a4af53c1a7031a5b490dd3be58620826872fe7b0f8ac60422e1f6e487a4974cf";

    /// <summary>What a test reports when the optional local reference material is absent.</summary>
    internal static string MissingSchemaMessage { get; } =
        "The authentic ASiC schema attachment was not found under tempdocs/etsi-ades-reference; it is optional local reference material, not a repository asset.";

    /// <summary>The XML Signature declarations the ASiC schema imports, written out rather than fetched.</summary>
    private static string DigitalSignatureSchema { get; } =
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
          targetNamespace="http://www.w3.org/2000/09/xmldsig#" elementFormDefault="qualified">
          <xsd:element name="DigestMethod" type="ds:DigestMethodType"/>
          <xsd:complexType name="DigestMethodType" mixed="true">
            <xsd:sequence>
              <xsd:any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
            </xsd:sequence>
            <xsd:attribute name="Algorithm" type="xsd:anyURI" use="required"/>
          </xsd:complexType>
          <xsd:element name="DigestValue" type="ds:DigestValueType"/>
          <xsd:simpleType name="DigestValueType">
            <xsd:restriction base="xsd:base64Binary"/>
          </xsd:simpleType>
          <xsd:element name="Signature" type="ds:SignatureType"/>
          <xsd:complexType name="SignatureType" mixed="true">
            <xsd:sequence>
              <xsd:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
            </xsd:sequence>
            <xsd:attribute name="Id" type="xsd:ID" use="optional"/>
          </xsd:complexType>
        </xsd:schema>
        """;


    /// <summary>
    /// Finds the authentic schema attachment by the SHA-256 Annex A.3 states for it.
    /// </summary>
    /// <returns>The schema's path, or <see langword="null"/> when no file of that digest is present.</returns>
    internal static async Task<string?> TryFindAuthenticSchemaAsync()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference");
        if(!Directory.Exists(referenceMaterial))
        {
            return null;
        }

        foreach(string candidate in Directory.EnumerateFiles(referenceMaterial, "*.xsd", SearchOption.AllDirectories))
        {
            var info = new FileInfo(candidate);
            if(info.Length is 0 or > 64 * 1024)
            {
                continue;
            }

            byte[] octets = await File.ReadAllBytesAsync(candidate).ConfigureAwait(false);
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                octets, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag, BaseMemoryPool.Shared).ConfigureAwait(false);

            if(string.Equals(Convert.ToHexStringLower(digest.AsReadOnlySpan()), AuthenticSchemaDigest, StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        return null;
    }


    /// <summary>
    /// Validates a manifest document against the authentic schema plus the two XML Signature declarations it
    /// imports.
    /// </summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="schemaPath">The authentic schema's path.</param>
    /// <returns>Every problem the validation reported; empty when the document is schema-valid.</returns>
    internal static List<string> Validate(ReadOnlySpan<byte> document, string schemaPath)
    {
        List<string> problems = [];
        var readerSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var schemas = new XmlSchemaSet { XmlResolver = null };

        using(var signatureSchemaText = new StringReader(DigitalSignatureSchema))
        using(XmlReader signatureSchemaReader = XmlReader.Create(signatureSchemaText, readerSettings))
        {
            _ = schemas.Add(null, signatureSchemaReader);
        }

        using(XmlReader asicSchemaReader = XmlReader.Create(schemaPath, readerSettings))
        {
            _ = schemas.Add(null, asicSchemaReader);
        }

        schemas.Compile();

        XDocument parsed = XDocument.Parse(Encoding.UTF8.GetString(document));
        parsed.Validate(schemas, (_, arguments) => problems.Add(arguments.Message));

        return problems;
    }
}
