using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>SigReference</c> element of a manifest — the one file the manifest is about, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2's <c>SigReferenceType</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What the reference means depends on the manifest's role, and the role is not in this type.</strong>
/// Annex A.4.1 states the fork: when the referenced file is a CAdES object or a time-stamp token, the
/// signature or token "shall apply to the file containing the <c>ASiCManifest</c> element" — the manifest
/// itself; when it is an Evidence Record, the record applies to the files the sibling
/// <see cref="AsicDataObjectReference"/> elements name, and the clause 4.4.4.2 NOTE 2 says explicitly that
/// the manifest file is then not covered. A caller learns which of the two it has from
/// <see cref="AsicManifestNaming.RoleFromEntryName"/>, applied to the name the manifest is stored under.
/// </para>
/// <para>
/// <see cref="Uri"/> is carried as it was written. Resolve it with
/// <see cref="AsicContainerUri.Resolve(string?)"/>, which reads it against the container root as Annex A.6
/// item 2 requires.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Annex A.6 item 2 makes a manifest reference a relative URI resolved against the container ROOT. System.Uri cannot hold a relative reference without a base, and constructing one against a base is exactly the resolution that annex forbids; the value is carried verbatim — it is also part of the octets a signature commits to — and resolved by AsicContainerUri.")]
public sealed record AsicSignatureReference
{
    /// <summary>
    /// The <c>URI</c> attribute (required by the schema): a relative reference naming the CAdES object, the
    /// time-stamp token or the Evidence Record this manifest is about.
    /// </summary>
    public required string Uri { get; init; }

    /// <summary>
    /// The <c>MimeType</c> attribute (optional): the media type of the referenced file. Annex A.4.2 calls it
    /// descriptive — nothing is validated against it.
    /// </summary>
    public string? MimeType { get; init; }


    /// <summary>A short debugger string showing what the manifest is about.</summary>
    private string DebuggerDisplay => $"AsicSignatureReference({Uri}, {MimeType ?? "no media type"})";
}


/// <summary>
/// One <c>Extension</c> element of a manifest, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2's <c>ExtensionType</c>: arbitrary content carrying a required
/// <c>Critical</c> attribute.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The content is carried, not interpreted.</strong> The schema types it as <c>AnyType</c> — mixed
/// content with <c>xsd:any processContents="lax"</c> — so no model this library could write would describe
/// it. <see cref="Content"/> therefore holds the extension element exactly as the serialisation seam produced
/// or found it, and <see cref="ElementNamespace"/>/<see cref="ElementName"/> name the first child element so
/// that a caller can decide whether it recognises the extension without parsing it again.
/// </para>
/// <para>
/// <strong><see cref="Critical"/> has no validator semantics anywhere in the specification.</strong> Annex
/// A.4.2 declares the attribute <c>use="required"</c> and neither A.4.1's semantics prose nor any clause of
/// Part 1 or Part 2 states what a validator does differently for <see langword="true"/>. This library's
/// answer is <see cref="AsicManifestExtensionPolicy"/>: an unrecognised critical extension fails closed,
/// because the producer marked it as something a consumer may not ignore and no consumer can weigh what it
/// cannot read.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="Content"/>; disposing the manifest that carries it
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicManifestExtension: IDisposable
{
    /// <summary>The <c>Critical</c> attribute (required by the schema).</summary>
    public required bool Critical { get; init; }

    /// <summary>
    /// The namespace of the extension's first child element, or <see langword="null"/> when the extension
    /// carries no element at all (the schema's mixed content admits text alone).
    /// </summary>
    public string? ElementNamespace { get; init; }

    /// <summary>
    /// The local name of the extension's first child element, or <see langword="null"/> when the extension
    /// carries no element at all.
    /// </summary>
    public string? ElementName { get; init; }

    /// <summary>
    /// The serialised octets of the whole <c>Extension</c> element, carried verbatim so that a manifest read
    /// and written again states the same extension. The instance owns them.
    /// </summary>
    public required PooledMemory Content { get; init; }


    /// <summary>Gets the qualified name of the extension's first child element, when it carries one.</summary>
    public AsicManifestExtensionName? Name =>
        ElementName is null ? null : new AsicManifestExtensionName(ElementNamespace ?? string.Empty, ElementName);


    /// <summary>Disposes <see cref="Content"/>.</summary>
    public void Dispose() => Content.Dispose();


    /// <summary>A short debugger string showing the extension's name and whether it is critical.</summary>
    private string DebuggerDisplay => $"AsicManifestExtension({ElementName ?? "text"}, critical: {Critical})";
}


/// <summary>
/// The qualified name of a manifest extension's content element — what a caller states it recognises.
/// </summary>
/// <param name="NamespaceName">The element's namespace, or the empty string when it has none.</param>
/// <param name="LocalName">The element's local name.</param>
[DebuggerDisplay("AsicManifestExtensionName: {{{NamespaceName}}}{LocalName}")]
public readonly record struct AsicManifestExtensionName(string NamespaceName, string LocalName);


/// <summary>
/// One <c>DataObjectReference</c> element of a manifest, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2's <c>DataObjectReferenceType</c>: one referenced file object,
/// its digest, and the two attributes that qualify it.
/// </summary>
/// <remarks>
/// <para>
/// Annex A.4.2 makes the cardinality exact: "There shall be one <c>DataObjectReference</c> element for each
/// file object referenced by <c>ASiCManifest</c>", and <c>ds:DigestValue</c> "shall contain the digest of the
/// file object's content, using the algorithm named by <c>ds:DigestMethod</c>". Recomputing that digest and
/// comparing it is what clause 4.4.4.2 item d makes an unconditional failure when it differs.
/// </para>
/// <para>
/// <strong>The algorithm is resolved, not carried as text.</strong> The wire form is a URI, which
/// <see cref="XmlSignatureWellKnown.DigestAlgorithmFromUri"/> maps onto the registry the digest seam
/// dispatches on. A serialisation seam that meets a URI it cannot resolve refuses the document rather than
/// building a reference whose algorithm nothing can compute, so an instance of this type always names an
/// algorithm this library will actually run.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="Digest"/> and every <see cref="Extensions"/> entry;
/// disposing the manifest that carries it disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Annex A.6 item 2 makes a manifest reference a relative URI resolved against the container ROOT. System.Uri cannot hold a relative reference without a base, and constructing one against a base is exactly the resolution that annex forbids; the value is carried verbatim — it is also part of the octets a signature commits to — and resolved by AsicContainerUri.")]
public sealed record AsicDataObjectReference: IDisposable
{
    /// <summary>The <c>URI</c> attribute (required by the schema): a relative reference naming the file object.</summary>
    public required string Uri { get; init; }

    /// <summary>The algorithm the <c>ds:DigestMethod</c> element named, resolved onto the registered digest seam.</summary>
    public required PkiDigestAlgorithm DigestAlgorithm { get; init; }

    /// <summary>The <c>ds:DigestValue</c> element's octets. The instance owns them.</summary>
    public required DigestValue Digest { get; init; }

    /// <summary>
    /// The <c>MimeType</c> attribute (optional), which Annex A.4.1 item 3 requires the element to "allow to
    /// indicate": the media type of the referenced file object.
    /// </summary>
    public string? MimeType { get; init; }

    /// <summary>
    /// The <c>Rootfile</c> attribute, or <see langword="null"/> when the document stated none.
    /// </summary>
    /// <remarks>
    /// The attribute carries two unrelated meanings depending on the manifest's role. Annex A.4.2 defines it
    /// as the root-file marker of the container format the vocabulary is borrowed from, while Annex A.7
    /// item 2 b) i) uses it inside an <c>ASiCArchiveManifest</c> as the backward pointer to the previous
    /// archive manifest of the chain. Absence and <see langword="false"/> are kept apart because the chain walk
    /// reads the presence of the attribute, not only its value.
    /// </remarks>
    public bool? IsRootFile { get; init; }

    /// <summary>The <c>DataObjectReferenceExtensions</c> element's extensions, when the document carried any.</summary>
    public IReadOnlyList<AsicManifestExtension> Extensions { get; init; } = [];


    /// <summary>Disposes <see cref="Digest"/> and every <see cref="Extensions"/> entry.</summary>
    public void Dispose()
    {
        Digest.Dispose();
        foreach(AsicManifestExtension extension in Extensions)
        {
            extension.Dispose();
        }
    }


    /// <summary>A short debugger string showing what is referenced and under which algorithm.</summary>
    private string DebuggerDisplay => $"AsicDataObjectReference({Uri}, {DigestAlgorithm.Identifier.Oid}, root file: {IsRootFile?.ToString() ?? "unstated"})";
}


/// <summary>
/// One <c>ASiCManifest</c> element instance — the single XML type that serves all three manifest roles, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.
/// </summary>
/// <remarks>
/// <para>
/// <strong>One model, three roles, and the role is not here.</strong> Clause 3.1 defines <c>ASiCManifest</c>,
/// <c>ASiCArchiveManifest</c> and <c>ASiCEvidenceRecordManifest</c>, Annex A.7 item 2 requires an archive
/// manifest to "contain one <c>ASiCManifest</c> element instance conformant to clause A.4", and clause
/// 4.4.3.2 item 4 requires the same of an Evidence Record manifest. Nothing in the schema distinguishes them.
/// The role travels beside an instance of this type as an <see cref="AsicManifestRole"/> derived from the file
/// name — see <see cref="AsicManifestNaming.RoleFromEntryName"/> — and never inside it, because a document
/// that stated its own role could disagree with the name it is dispatched by.
/// </para>
/// <para>
/// <strong>Serialisation-agnostic.</strong> This is a plain model: it names no XML type and this project
/// references no XML package. Reading and writing reach the library as
/// <see cref="ParseAsicManifestDelegate"/> and <see cref="EncodeAsicManifestDelegate"/>, the same pattern
/// <see cref="ParseTrustedListDelegate"/> established.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every reference and extension it carries; the caller disposes
/// it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AsicManifest: IDisposable
{
    /// <summary>The <c>SigReference</c> element (exactly one, per the schema's sequence).</summary>
    public required AsicSignatureReference SignatureReference { get; init; }

    /// <summary>
    /// The <c>DataObjectReference</c> elements (one or more, per the schema's <c>maxOccurs="unbounded"</c> on a
    /// required particle), one for each file object the manifest references.
    /// </summary>
    public required IReadOnlyList<AsicDataObjectReference> DataObjectReferences { get; init; }

    /// <summary>The <c>ASiCManifestExtensions</c> element's extensions, when the document carried any.</summary>
    public IReadOnlyList<AsicManifestExtension> Extensions { get; init; } = [];


    /// <summary>Disposes every reference and extension this manifest owns.</summary>
    public void Dispose()
    {
        foreach(AsicDataObjectReference reference in DataObjectReferences)
        {
            reference.Dispose();
        }

        foreach(AsicManifestExtension extension in Extensions)
        {
            extension.Dispose();
        }
    }


    /// <summary>A short debugger string showing what the manifest is about and how much it references.</summary>
    private string DebuggerDisplay => $"AsicManifest({SignatureReference.Uri}, {DataObjectReferences.Count} data objects)";
}


/// <summary>
/// Whether a manifest's extensions are ones a consumer may proceed on.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised status never reads as accepted.
/// </remarks>
public enum AsicManifestExtensionStatus
{
    /// <summary>No evaluation has been performed. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>Every critical extension is one the caller stated it recognises.</summary>
    Accepted = 1,

    /// <summary>An extension marked critical carries content the caller did not state it recognises.</summary>
    UnrecognizedCriticalExtension = 2
}


/// <summary>
/// The outcome of evaluating a manifest's extensions.
/// </summary>
/// <param name="Status">Whether the manifest may be proceeded on.</param>
/// <param name="RejectedExtension">
/// The name of the extension that stopped the evaluation, when one did. <see langword="null"/> when the
/// refused extension carried no element at all, which is itself unrecognisable.
/// </param>
[DebuggerDisplay("AsicManifestExtensionEvaluation: {Status}")]
public readonly record struct AsicManifestExtensionEvaluation(
    AsicManifestExtensionStatus Status,
    AsicManifestExtensionName? RejectedExtension)
{
    /// <summary>Gets whether every critical extension is recognised.</summary>
    public bool IsAccepted => Status == AsicManifestExtensionStatus.Accepted;
}


/// <summary>
/// What a consumer recognises among a manifest's <c>Extension</c> elements, and what it does with the ones it
/// does not.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why a policy exists at all.</strong> Annex A.4.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> makes <c>Critical</c> a required attribute of every <c>Extension</c> and
/// then never states a consumer obligation for it. The secure reading is the one the attribute's name carries
/// and the one every comparable mechanism uses: a producer marking an extension critical is stating that a
/// consumer which cannot interpret it must not proceed as though it were absent. <see cref="Strict"/> is
/// therefore the default, and <see cref="AcceptUnrecognizedCriticalExtensions"/> is the documented departure
/// a caller has to state for itself.
/// </para>
/// <para>
/// A non-critical extension is never a reason to stop, whether recognised or not — that is what the
/// attribute's other value means.
/// </para>
/// </remarks>
public sealed record AsicManifestExtensionPolicy
{
    /// <summary>The default policy: nothing is recognised and an unrecognised critical extension stops the evaluation.</summary>
    public static AsicManifestExtensionPolicy Strict { get; } = new();

    /// <summary>The extension content elements the caller states it recognises.</summary>
    public IReadOnlyList<AsicManifestExtensionName> RecognizedExtensions { get; init; } = [];

    /// <summary>
    /// Whether an extension marked critical that the caller does not recognise is accepted anyway. The
    /// documented departure from the secure default; <see langword="false"/> unless a caller states otherwise.
    /// </summary>
    public bool AcceptUnrecognizedCriticalExtensions { get; init; }


    /// <summary>
    /// Evaluates a manifest's own extensions and those of every data object reference it carries.
    /// </summary>
    /// <param name="manifest">The manifest to evaluate.</param>
    /// <returns>The evaluation.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="manifest"/> is <see langword="null"/>.</exception>
    public AsicManifestExtensionEvaluation Evaluate(AsicManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        AsicManifestExtensionEvaluation evaluation = Evaluate(manifest.Extensions);
        if(!evaluation.IsAccepted)
        {
            return evaluation;
        }

        foreach(AsicDataObjectReference reference in manifest.DataObjectReferences)
        {
            evaluation = Evaluate(reference.Extensions);
            if(!evaluation.IsAccepted)
            {
                return evaluation;
            }
        }

        return new AsicManifestExtensionEvaluation(AsicManifestExtensionStatus.Accepted, null);
    }


    /// <summary>
    /// Evaluates one list of extensions.
    /// </summary>
    /// <param name="extensions">The extensions to evaluate.</param>
    /// <returns>The evaluation.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="extensions"/> is <see langword="null"/>.</exception>
    public AsicManifestExtensionEvaluation Evaluate(IReadOnlyList<AsicManifestExtension> extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        if(AcceptUnrecognizedCriticalExtensions)
        {
            return new AsicManifestExtensionEvaluation(AsicManifestExtensionStatus.Accepted, null);
        }

        foreach(AsicManifestExtension extension in extensions)
        {
            if(!extension.Critical)
            {
                continue;
            }

            AsicManifestExtensionName? name = extension.Name;
            if(name is null || !IsRecognized(name.Value))
            {
                return new AsicManifestExtensionEvaluation(AsicManifestExtensionStatus.UnrecognizedCriticalExtension, name);
            }
        }

        return new AsicManifestExtensionEvaluation(AsicManifestExtensionStatus.Accepted, null);
    }


    /// <summary>
    /// Determines whether a qualified name is among <see cref="RecognizedExtensions"/>.
    /// </summary>
    /// <param name="name">The extension content element's qualified name.</param>
    /// <returns><see langword="true"/> when the caller stated it recognises it.</returns>
    private bool IsRecognized(AsicManifestExtensionName name)
    {
        for(int i = 0; i < RecognizedExtensions.Count; ++i)
        {
            if(RecognizedExtensions[i] == name)
            {
                return true;
            }
        }

        return false;
    }
}
