using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// The complete content of a transparent elementary file read from a contactless IC — for example
/// EF.COM, EF.SOD, or a data group — assembled from one or more READ BINARY operations.
/// </summary>
/// <remarks>
/// <para>
/// A read elementary file is a tracked carrier rather than a naked buffer: it owns its pooled memory,
/// clears it on disposal, and names the file it came from. Parsers (EF.COM, the LDS Security Object)
/// and Passive Authentication consume its <see cref="Content"/>; the bytes are never handed around as
/// an unowned array.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ElementaryFile : SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="ElementaryFile"/> from owned file bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the file content. Ownership transfers to this instance.</param>
    /// <param name="fileIdentifier">The two-byte elementary file identifier the content was read from.</param>
    public ElementaryFile(IMemoryOwner<byte> storage, ushort fileIdentifier)
        : base(storage, ApduTags.ElementaryFile)
    {
        ArgumentNullException.ThrowIfNull(storage);
        FileIdentifier = fileIdentifier;
    }


    /// <summary>Gets the elementary file identifier the content was read from.</summary>
    public ushort FileIdentifier { get; }

    /// <summary>Gets the length of the file content in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>Gets the file content.</summary>
    public ReadOnlySpan<byte> Content => MemoryOwner.Memory.Span;


    private string DebuggerDisplay => $"ElementaryFile(0x{FileIdentifier:X4}, {Length} bytes)";
}
