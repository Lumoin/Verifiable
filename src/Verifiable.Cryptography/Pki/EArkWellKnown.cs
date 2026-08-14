using System;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The names the E-ARK Common Specification for Information Packages fixes for a package's own files and
/// folders, together with the recognition helpers a rule uses instead of comparing string literals at the call
/// site.
/// </summary>
/// <remarks>
/// <para>
/// Every value here is stated by
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause 4.1</see>:
/// the manifest file name by <c>CSIPSTR4</c> and <c>CSIPSTR12</c>, the metadata folder by <c>CSIPSTR5</c> and
/// its two named sub-folders by <c>CSIPSTR6</c> and <c>CSIPSTR7</c>, the further metadata sub-folder by
/// <c>CSIPSTR8</c>, the representations folder and a representation's data folder by <c>CSIPSTR9</c> to
/// <c>CSIPSTR11</c>, the schema folder by <c>CSIPSTR15</c> and the documentation folder by <c>CSIPSTR16</c>.
/// </para>
/// <para>
/// <strong>Comparisons are ordinal.</strong> The specification states these names literally and packages are
/// exchanged between file systems that do not agree on case; matching case-insensitively would admit a package
/// whose entries a conforming reader on a case-sensitive file system cannot find. The names this library
/// <em>writes</em> are the exact forms named here.
/// </para>
/// </remarks>
public static class EArkWellKnown
{
    /// <summary>The separator an entry name inside a package uses, <c>/</c>, whichever file system the package came from.</summary>
    public static char PathSeparator { get; } = '/';

    /// <summary>The name of the manifest file at the root of a package and of each representation, <c>METS.xml</c> (<c>CSIPSTR4</c>, <c>CSIPSTR12</c>).</summary>
    public static string PackageManifestFileName { get; } = "METS.xml";

    /// <summary>The name of the folder holding whole-package metadata, <c>metadata</c> (<c>CSIPSTR5</c>).</summary>
    public static string MetadataFolderName { get; } = "metadata";

    /// <summary>The name of the folder holding preservation metadata, <c>metadata/preservation</c> (<c>CSIPSTR6</c>).</summary>
    public static string PreservationMetadataFolderName { get; } = "metadata/preservation";

    /// <summary>The name of the folder holding descriptive metadata, <c>metadata/descriptive</c> (<c>CSIPSTR7</c>).</summary>
    public static string DescriptiveMetadataFolderName { get; } = "metadata/descriptive";

    /// <summary>The name of the folder holding metadata of any other kind, <c>metadata/other</c> (<c>CSIPSTR8</c>).</summary>
    public static string OtherMetadataFolderName { get; } = "metadata/other";

    /// <summary>The last path segment of <see cref="PreservationMetadataFolderName"/>, <c>preservation</c>, which a tree classifier compares one segment against (<c>CSIPSTR6</c>).</summary>
    public static string PreservationMetadataSubFolderName { get; } = "preservation";

    /// <summary>The last path segment of <see cref="DescriptiveMetadataFolderName"/>, <c>descriptive</c> (<c>CSIPSTR7</c>).</summary>
    public static string DescriptiveMetadataSubFolderName { get; } = "descriptive";

    /// <summary>The last path segment of <see cref="OtherMetadataFolderName"/>, <c>other</c> (<c>CSIPSTR8</c>).</summary>
    public static string OtherMetadataSubFolderName { get; } = "other";

    /// <summary>The name of the folder holding the representations, <c>representations</c> (<c>CSIPSTR9</c>).</summary>
    public static string RepresentationsFolderName { get; } = "representations";

    /// <summary>The name of the sub-folder inside a representation that holds its data, <c>data</c> (<c>CSIPSTR11</c>).</summary>
    public static string RepresentationDataFolderName { get; } = "data";

    /// <summary>The name of the folder holding the XML schema documents, <c>schemas</c> (<c>CSIPSTR15</c>).</summary>
    public static string SchemasFolderName { get; } = "schemas";

    /// <summary>The name of the folder holding the supplementary documentation, <c>documentation</c> (<c>CSIPSTR16</c>).</summary>
    public static string DocumentationFolderName { get; } = "documentation";


    /// <summary>Determines whether an entry name is the manifest file at the package root (<c>CSIPSTR4</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is exactly the root manifest.</returns>
    public static bool IsPackageManifestEntryName(string? entryName) =>
        string.Equals(entryName, PackageManifestFileName, StringComparison.Ordinal);


    /// <summary>Determines whether an entry name is the metadata folder or something inside it (<c>CSIPSTR5</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsMetadataEntryName(string? entryName) =>
        IsWithinFolder(entryName, MetadataFolderName);


    /// <summary>Determines whether an entry name is the preservation-metadata folder or something inside it (<c>CSIPSTR6</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsPreservationMetadataEntryName(string? entryName) =>
        IsWithinFolder(entryName, PreservationMetadataFolderName);


    /// <summary>Determines whether an entry name is the descriptive-metadata folder or something inside it (<c>CSIPSTR7</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsDescriptiveMetadataEntryName(string? entryName) =>
        IsWithinFolder(entryName, DescriptiveMetadataFolderName);


    /// <summary>Determines whether an entry name is the further-metadata folder or something inside it (<c>CSIPSTR8</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsOtherMetadataEntryName(string? entryName) =>
        IsWithinFolder(entryName, OtherMetadataFolderName);


    /// <summary>Determines whether an entry name is the representations folder or something inside it (<c>CSIPSTR9</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsRepresentationsEntryName(string? entryName) =>
        IsWithinFolder(entryName, RepresentationsFolderName);


    /// <summary>Determines whether an entry name is the schema folder or something inside it (<c>CSIPSTR15</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsSchemasEntryName(string? entryName) =>
        IsWithinFolder(entryName, SchemasFolderName);


    /// <summary>Determines whether an entry name is the documentation folder or something inside it (<c>CSIPSTR16</c>).</summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the name is that folder or lies below it.</returns>
    public static bool IsDocumentationEntryName(string? entryName) =>
        IsWithinFolder(entryName, DocumentationFolderName);


    /// <summary>
    /// Determines whether an entry name names a folder itself or something inside it. The folder's own entry
    /// may arrive with or without the trailing separator an archive writes for an empty folder, and both forms
    /// name the folder.
    /// </summary>
    /// <param name="entryName">The entry name, root-relative and <c>/</c>-separated, or <see langword="null"/>.</param>
    /// <param name="folderName">The folder name, root-relative, without a trailing separator.</param>
    /// <returns><see langword="true"/> when the entry is that folder or lies below it.</returns>
    public static bool IsWithinFolder(string? entryName, string folderName)
    {
        ArgumentException.ThrowIfNullOrEmpty(folderName);

        if(string.IsNullOrEmpty(entryName))
        {
            return false;
        }

        if(string.Equals(entryName, folderName, StringComparison.Ordinal))
        {
            return true;
        }

        return entryName.Length > folderName.Length
            && entryName.StartsWith(folderName, StringComparison.Ordinal)
            && entryName[folderName.Length] == PathSeparator;
    }
}
