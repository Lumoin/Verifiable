using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Foundation;


/// <summary>
/// Base class for sensitive data that carries metadata via <see cref="Tag"/>.
/// </summary>
public abstract class SensitiveData
{
    /// <summary>
    /// Gets the metadata tag describing this sensitive data.
    /// </summary>
    public Tag Tag { get; }


    /// <summary>
    /// Initializes a new instance with the specified tag.
    /// </summary>
    /// <param name="tag">Tags the data with out-of-band information such as algorithm and purpose.</param>
    protected SensitiveData(Tag tag)
    {
        ArgumentNullException.ThrowIfNull(tag, nameof(tag));
        Tag = tag;
    }
}


/// <summary>
/// Base class for a pooled, tagged block of sensitive memory whose lifetime can be observed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Architecture Overview</strong>
/// </para>
/// <para>
/// This is a domain-agnostic secure-memory primitive: it owns an <see cref="IMemoryOwner{T}"/>,
/// carries a <see cref="Tag"/> of out-of-band metadata, clears its bytes on disposal, and optionally
/// bounds an OpenTelemetry span to its lifetime. Higher layers build on it — for cryptographic
/// material it is the foundation of a layered key hierarchy across multiple backends (software, TPM,
/// HSM, cloud KMS, browser Web Crypto) — but nothing here is specific to cryptography.
/// </para>
/// <para>
/// <strong>OpenTelemetry Lifetime Spans</strong>
/// </para>
/// <para>
/// When an <see cref="Activity"/> is supplied at construction, this class manages its lifetime —
/// stopping it in <see cref="Dispose(bool)"/> and tagging it with
/// <see cref="SensitiveMemoryTelemetry.LifetimeMs"/> at that point. The caller starts the activity
/// before construction and stamps it with whatever domain-specific provenance attributes it needs
/// (for cryptographic material the crypto backend stamps its provider / library / class / operation
/// attributes for CBOM traceability); this primitive contributes only the neutral lifetime duration.
/// </para>
/// <para>
/// If no OTel listener is configured, <see cref="ActivitySource.StartActivity"/> returns
/// <see langword="null"/> and the <c>activity</c> parameter should be passed as
/// <see langword="null"/>. The constructor accepts <see langword="null"/> and the
/// entire path is zero-cost.
/// </para>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="SensitiveMemoryTelemetry"/>
public abstract class SensitiveMemory: SensitiveData, IDisposable, IEquatable<SensitiveMemory>
{
    private bool disposed;
    private readonly Activity? lifetime;

    /// <summary>
    /// The piece of sensitive data.
    /// </summary>
    protected IMemoryOwner<byte> MemoryOwner { get; }


    /// <summary>
    /// Initializes a new instance of <see cref="SensitiveMemory"/>.
    /// </summary>
    /// <param name="sensitiveMemory">
    /// The memory owner holding the sensitive bytes. Ownership transfers to this instance.
    /// </param>
    /// <param name="tag">
    /// Metadata describing the contents — e.g. algorithm, purpose, encoding, and provenance.
    /// A caller layering a specific domain on top stamps its own entries here (for cryptographic
    /// material the crypto backend stamps provider / library / class / operation entries for CBOM
    /// traceability).
    /// </param>
    /// <param name="lifetime">
    /// An optional OTel <see cref="Activity"/> spanning the lifetime of this value.
    /// Started by the backend before construction; stopped by <see cref="Dispose()"/>.
    /// Pass <see langword="null"/> when no OTel listener is active — the constructor
    /// is zero-cost in that case.
    /// </param>
    protected SensitiveMemory(
        IMemoryOwner<byte> sensitiveMemory,
        Tag tag,
        Activity? lifetime = null) : base(tag)
    {
        ArgumentNullException.ThrowIfNull(sensitiveMemory);
        MemoryOwner = sensitiveMemory;
        this.lifetime = lifetime;
    }


    /// <summary>
    /// Exposes the internal sensitive memory as a read-only span.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return MemoryOwner.Memory.Span;
    }


    /// <summary>
    /// Exposes the internal sensitive memory as read-only memory.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if this instance has been disposed.</exception>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return MemoryOwner.Memory;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Releases resources held by this instance and stops the OTel lifetime span
    /// if one was supplied at construction.
    /// </summary>
    /// <param name="disposing">
    /// <see langword="true"/> if called from <see cref="Dispose()"/>;
    /// <see langword="false"/> if called from a finalizer.
    /// </param>
    protected virtual void Dispose(bool disposing)
    {
        if(disposed)
        {
            return;
        }

        //Shared empty instances backed by EmptyMemoryOwner are singletons
        //that must never be disposed. Their Dispose is a no-op, but setting
        //the disposed flag would poison all future users of the singleton.
        if(MemoryOwner is EmptyMemoryOwner)
        {
            return;
        }

        if(disposing)
        {
            //Clearing the memory is in case there is not a pooled memory owner
            //that clears it. One example is Verifiable.Core.ExactSizeMemoryPool.
            MemoryOwner.Memory.Span.Clear();
            MemoryOwner.Dispose();

            if(lifetime is not null)
            {
                lifetime.Stop();
                lifetime.SetTag(SensitiveMemoryTelemetry.LifetimeMs,
                    lifetime.Duration.TotalMilliseconds);
            }
        }

        disposed = true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] SensitiveMemory? other)
    {
        return other is not null
            && MemoryExtensions.SequenceEqual(
                MemoryOwner.Memory.Span,
                other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is SensitiveMemory s && Equals(s);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in SensitiveMemory s1, in SensitiveMemory s2) => Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in SensitiveMemory s1, in SensitiveMemory s2) => !Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object s1, in SensitiveMemory s2) => Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in SensitiveMemory s1, in object s2) => Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object s1, in SensitiveMemory s2) => !Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in SensitiveMemory s1, in object s2) => !Equals(s1, s2);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        ReadOnlySpan<byte> memorySpan = MemoryOwner.Memory.Span;
        for(int i = 0; i < memorySpan.Length; ++i)
        {
            hash.Add(memorySpan[i].GetHashCode());
        }

        return hash.ToHashCode();
    }
}