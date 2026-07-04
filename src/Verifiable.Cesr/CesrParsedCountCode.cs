namespace Verifiable.Cesr;

/// <summary>
/// The result of decoding a CESR count (group/framing) code from either domain: the stable code and the
/// soft count it carries. A count code owns no raw value, so unlike a primitive it holds no pooled memory
/// and need not be disposed.
/// </summary>
/// <param name="Code">
/// The stable (hard) part of the code, for example <c>-V</c> for an attachment group, <c>--V</c> for a big
/// attachment group, or <c>-_AAA</c> for the KERI/ACDC protocol genus.
/// </param>
/// <param name="Count">
/// The soft value: the number of quadlets (text domain) or triplets (binary domain) in the group that
/// follows, or, for a genus/version code, the packed protocol version (see <see cref="Version"/>).
/// </param>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#count-code-tables">
/// Count Code tables</see>. The count is invariant between the text and binary domains: it is the number of
/// quadlets in the text domain and the number of triplets in the binary domain, which describe the same
/// 24-bit-aligned span. This invariance is what lets a parser skip a group without parsing its contents.
/// </para>
/// </remarks>
public readonly record struct CesrParsedCountCode(string Code, int Count)
{
    /// <summary>
    /// Whether this is a protocol genus/version code, whose <see cref="Count"/> is a packed version rather
    /// than a quadlet/triplet count and which therefore cannot be used to frame a pipelineable group.
    /// </summary>
    public bool IsGenusVersion => CesrCountCodeTables.IsGenusVersionCode(Code);

    /// <summary>
    /// The three-character protocol genus of a genus/version code (the hard characters after the <c>-_</c>
    /// prefix), or <see langword="null"/> when this is an ordinary count code.
    /// </summary>
    public string? Genus => IsGenusVersion ? Code[2..] : null;

    /// <summary>
    /// The major and minor protocol version of a genus/version code, or <see langword="null"/> when this is
    /// an ordinary count code.
    /// </summary>
    public (int Major, int Minor)? Version => IsGenusVersion ? CesrCountCodeTables.UnpackVersion(Count) : null;

    /// <summary>
    /// The number of bytes the framed group occupies in the binary domain (<see cref="Count"/> triplets of
    /// three bytes). A <see cref="long"/> because a large count code frames up to <c>64^5 - 1</c> triplets, whose
    /// byte count exceeds <see cref="int"/> range: computing it as <see cref="int"/> would silently overflow to a
    /// negative value and defeat a consumer's length guard, so a consumer that materializes the group MUST
    /// range-check this against the bytes actually available before narrowing it. Not meaningful for a
    /// genus/version code.
    /// </summary>
    public long BinaryByteCount => (long)Count * 3;

    /// <summary>
    /// The number of characters the framed group occupies in the text domain (<see cref="Count"/> quadlets
    /// of four characters). A <see cref="long"/> for the same reason as <see cref="BinaryByteCount"/>: a large
    /// count code's quadlet count times four exceeds <see cref="int"/> range and must not be computed as
    /// <see cref="int"/>. Not meaningful for a genus/version code.
    /// </summary>
    public long TextCharCount => (long)Count * 4;
}
