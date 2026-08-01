using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Seal;

/// <summary>
/// The persistable result of <see cref="TpmDeviceExtensions.SealAsync"/>: the parent-wrapped private area and
/// the reserialized public area of a sealed <c>TPM_ALG_KEYEDHASH</c> object, decoupled from the
/// <see cref="CreateResponse"/> that produced them.
/// </summary>
/// <remarks>
/// <para>
/// This is what a caller persists to disk or a database between sessions: <see cref="GetSerializedSize"/> and
/// <see cref="WriteTo"/> write the wire form a caller stores, and the static <see cref="Parse"/> rebuilds an
/// independent instance from those bytes alone — the same disk round trip the seal flow tests perform by
/// copying the private blob and reserializing the public area (TPM 2.0 Library Part 3, Section 12.1, Table 20).
/// </para>
/// <para>
/// Both carriers are pooled and owned by this instance; dispose it once the blob is either persisted (its bytes
/// copied out via <see cref="WriteTo"/>) or consumed by <see cref="TpmDeviceExtensions.UnsealAsync"/> /
/// <see cref="TpmDeviceExtensions.UnsealUnderPolicyAsync"/>. Shaped like the sibling wire-response carriers
/// (<see cref="CreateResponse"/>, <see cref="Infrastructure.Commands.LoadResponse"/>) rather than as a record: no
/// value-equality contract is offered over pooled, disposable buffer ownership.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmSealedBlob: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the parent-wrapped private blob (<c>TPM2_Create</c>'s <c>outPrivate</c>) — opaque to every entity
    /// but the parent that wrapped it.
    /// </summary>
    public Tpm2bPrivate OutPrivate { get; }

    /// <summary>
    /// Gets the public area of the sealed object (<c>TPM2_Create</c>'s <c>outPublic</c>).
    /// </summary>
    public Tpm2bPublic OutPublic { get; }

    private TpmSealedBlob(Tpm2bPrivate outPrivate, Tpm2bPublic outPublic)
    {
        OutPrivate = outPrivate;
        OutPublic = outPublic;
    }

    /// <summary>
    /// Gets the serialized size of this sealed blob: <see cref="OutPrivate"/> then <see cref="OutPublic"/>, both
    /// TPM2B length-prefixed, exactly as <see cref="WriteTo"/> writes them.
    /// </summary>
    /// <returns>The size, in octets, that <see cref="WriteTo"/> writes.</returns>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return OutPrivate.SerializedSize + OutPublic.GetSerializedSize();
    }

    /// <summary>
    /// Writes this sealed blob to a TPM writer, <see cref="OutPrivate"/> then <see cref="OutPublic"/> — the
    /// disk/DB persistence format a caller round-trips through <see cref="Parse"/>.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        OutPrivate.WriteTo(ref writer);
        OutPublic.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a sealed blob previously written by <see cref="WriteTo"/> — the disk/DB round trip between a seal
    /// and a later unseal, reconstructing an instance with no ties to the TPM session that created it.
    /// </summary>
    /// <param name="reader">The reader positioned at a previously written sealed blob.</param>
    /// <param name="pool">The memory pool backing the parsed carriers.</param>
    /// <returns>The parsed sealed blob.</returns>
    public static TpmSealedBlob Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bPrivate outPrivate = Tpm2bPrivate.Parse(ref reader, pool);
        Tpm2bPublic outPublic = Tpm2bPublic.Parse(ref reader, pool);

        return new TpmSealedBlob(outPrivate, outPublic);
    }

    /// <summary>
    /// Builds a sealed blob from a <c>TPM2_Create</c> response, copying its outPrivate octets and reserializing
    /// its outPublic into independent pooled storage — the response itself is typically disposed by the caller
    /// immediately after this call returns, so this instance must not alias its storage.
    /// </summary>
    /// <param name="response">The Create response for a sealed KEYEDHASH object.</param>
    /// <param name="pool">The memory pool backing the copied carriers.</param>
    /// <returns>The sealed blob.</returns>
    internal static TpmSealedBlob FromCreateResponse(CreateResponse response, BaseMemoryPool pool)
    {
        Tpm2bPrivate outPrivate = Tpm2bPrivate.Create(response.OutPrivate.Span, pool);
        Tpm2bPublic outPublic = ClonePublicArea(response.OutPublic, pool);

        return new TpmSealedBlob(outPrivate, outPublic);
    }

    /// <summary>
    /// Creates an independent copy of this sealed blob's <see cref="OutPrivate"/> and <see cref="OutPublic"/>,
    /// suitable for handing to a <see cref="LoadInput"/> — which takes ownership of (and disposes) the buffers
    /// it is constructed with — while leaving this instance intact for a subsequent load/unseal attempt.
    /// </summary>
    /// <param name="pool">The memory pool backing the copies.</param>
    /// <returns>A private/public pair independent of this instance's storage.</returns>
    internal (Tpm2bPrivate InPrivate, Tpm2bPublic InPublic) CloneForLoad(BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(OutPrivate.Span, pool);
        Tpm2bPublic inPublic = ClonePublicArea(OutPublic, pool);

        return (inPrivate, inPublic);
    }

    /// <summary>
    /// Releases the pooled storage backing <see cref="OutPrivate"/> and <see cref="OutPublic"/>.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            OutPrivate.Dispose();
            OutPublic.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// Reserializes a public area into a fresh <see cref="Tpm2bPublic"/> backed by independent pooled storage —
    /// the round-trip a disk-persisted public blob makes, keeping the returned copy's lifetime independent of
    /// <paramref name="source"/>.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    private static Tpm2bPublic ClonePublicArea(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    private string DebuggerDisplay => $"TpmSealedBlob(private={OutPrivate.Length} bytes, {OutPublic.PublicArea.Type})";
}
