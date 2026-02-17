using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Verifiable.Core.SelectiveDisclosure;
using JsonPointerType = Verifiable.JsonPointer.JsonPointer;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Represents a DCQL claim path pattern that may contain wildcards.
/// </summary>
/// <remarks>
/// <para>
/// In the DCQL specification, <c>claim_path</c> is a JSON array where each element
/// is either a string (property name), a non-negative integer (array index), or
/// <c>null</c> (wildcard matching all array elements). For example:
/// </para>
/// <list type="bullet">
/// <item><description><c>["given_name"]</c> — a concrete single-element path.</description></item>
/// <item><description><c>["address", "city"]</c> — a concrete multi-element path.</description></item>
/// <item><description><c>["items", null, "name"]</c> — a pattern with a wildcard.</description></item>
/// </list>
/// <para>
/// When a pattern contains no wildcards, it resolves directly to a <see cref="CredentialPath"/>.
/// When it contains wildcards, it must be matched against a credential's actual structure
/// by the evaluator to produce concrete <see cref="CredentialPath"/> values.
/// </para>
/// <para>
/// <strong>Thread safety:</strong> This type is immutable and thread-safe.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public sealed class DcqlClaimPattern: IEquatable<DcqlClaimPattern>
{
    private readonly PatternSegment[] segments;

    /// <summary>
    /// The number of segments in this pattern.
    /// </summary>
    public int Count => segments.Length;

    /// <summary>
    /// Gets the segment at the specified index.
    /// </summary>
    public PatternSegment this[int index] => segments[index];

    /// <summary>
    /// Whether this pattern contains any wildcard segments.
    /// </summary>
    public bool HasWildcards
    {
        get
        {
            foreach(var segment in segments)
            {
                if(segment.IsWildcard)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Creates a pattern from an array of segments.
    /// </summary>
    /// <param name="segments">The pattern segments.</param>
    /// <exception cref="ArgumentNullException">Thrown when segments is null.</exception>
    /// <exception cref="ArgumentException">Thrown when segments is empty.</exception>
    public DcqlClaimPattern(params PatternSegment[] segments)
    {
        ArgumentNullException.ThrowIfNull(segments);

        if(segments.Length == 0)
        {
            throw new ArgumentException("A claim pattern must have at least one segment.", nameof(segments));
        }

        this.segments = (PatternSegment[])segments.Clone();
    }


    /// <summary>
    /// Creates a concrete pattern (no wildcards) from property name keys.
    /// </summary>
    /// <param name="keys">One or more property name keys.</param>
    /// <returns>A new pattern with key segments.</returns>
    public static DcqlClaimPattern FromKeys(params string[] keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        if(keys.Length == 0)
        {
            throw new ArgumentException("At least one key is required.", nameof(keys));
        }

        var result = new PatternSegment[keys.Length];
        for(int i = 0; i < keys.Length; i++)
        {
            ArgumentNullException.ThrowIfNull(keys[i]);
            result[i] = PatternSegment.Key(keys[i]);
        }

        return new DcqlClaimPattern(result);
    }


    /// <summary>
    /// Creates a pattern for an mso_mdoc element (namespace + element identifier).
    /// </summary>
    /// <param name="nameSpace">The mdoc namespace (e.g., "org.iso.18013.5.1").</param>
    /// <param name="elementIdentifier">The element name (e.g., "given_name").</param>
    /// <returns>A two-segment pattern.</returns>
    public static DcqlClaimPattern ForMdoc(string nameSpace, string elementIdentifier)
    {
        ArgumentNullException.ThrowIfNull(nameSpace);
        ArgumentNullException.ThrowIfNull(elementIdentifier);

        return new DcqlClaimPattern(
            PatternSegment.Key(nameSpace),
            PatternSegment.Key(elementIdentifier));
    }


    /// <summary>
    /// Attempts to resolve this pattern to a concrete <see cref="CredentialPath"/>.
    /// </summary>
    /// <param name="credentialPath">The resolved path, if the pattern has no wildcards.</param>
    /// <returns>
    /// <see langword="true"/> if resolved (no wildcards); <see langword="false"/> if the
    /// pattern contains wildcards and requires evaluator-driven resolution.
    /// </returns>
    public bool TryResolve(out CredentialPath credentialPath)
    {
        if(HasWildcards)
        {
            credentialPath = default;
            return false;
        }

        var pointer = JsonPointerType.Root;
        foreach(var segment in segments)
        {
            if(segment.IsKey)
            {
                pointer = pointer.Append(segment.KeyValue!);
            }
            else if(segment.IsIndex)
            {
                pointer = pointer.Append(segment.IndexValue!.Value);
            }
        }

        credentialPath = new CredentialPath(pointer);
        return true;
    }


    /// <summary>
    /// Determines whether this pattern matches a concrete <see cref="CredentialPath"/>.
    /// </summary>
    /// <param name="path">The concrete path to match against.</param>
    /// <returns><see langword="true"/> if the pattern matches the path.</returns>
    public bool Matches(CredentialPath path)
    {
        if(!path.IsJsonPath)
        {
            return false;
        }

        var jsonPointer = path.JsonPointer;
        if(jsonPointer.Depth != segments.Length)
        {
            return false;
        }

        var pointerSegments = jsonPointer.Segments;
        for(int i = 0; i < segments.Length; i++)
        {
            var pattern = segments[i];
            var actual = pointerSegments[i];

            if(pattern.IsWildcard)
            {
                continue;
            }

            if(pattern.IsKey)
            {
                if(!string.Equals(pattern.KeyValue, actual.Value, StringComparison.Ordinal))
                {
                    return false;
                }
            }
            else if(pattern.IsIndex)
            {
                if(!actual.TryGetArrayIndex(out int actualIndex) || actualIndex != pattern.IndexValue!.Value)
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        var parts = new string[segments.Length];
        for(int i = 0; i < segments.Length; i++)
        {
            parts[i] = segments[i].ToString();
        }

        return $"[{string.Join(", ", parts)}]";
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(DcqlClaimPattern? other)
    {
        if(other is null || segments.Length != other.segments.Length)
        {
            return false;
        }

        for(int i = 0; i < segments.Length; i++)
        {
            if(!segments[i].Equals(other.segments[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => Equals(obj as DcqlClaimPattern);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(segments.Length);
        foreach(var segment in segments)
        {
            hash.Add(segment);
        }

        return hash.ToHashCode();
    }
}


/// <summary>
/// A single segment in a <see cref="DcqlClaimPattern"/>: a key, an index, or a wildcard.
/// </summary>
[DebuggerDisplay("{ToString()}")]
public readonly record struct PatternSegment
{
    /// <summary>
    /// The property name, when this is a key segment.
    /// </summary>
    public string? KeyValue { get; private init; }

    /// <summary>
    /// The array index, when this is an index segment.
    /// </summary>
    public int? IndexValue { get; private init; }

    /// <summary>
    /// Whether this is a key (property name) segment.
    /// </summary>
    public bool IsKey => KeyValue is not null;

    /// <summary>
    /// Whether this is an index (array position) segment.
    /// </summary>
    public bool IsIndex => IndexValue.HasValue;

    /// <summary>
    /// Whether this is a wildcard segment matching any array element.
    /// </summary>
    public bool IsWildcard => KeyValue is null && !IndexValue.HasValue;

    /// <summary>
    /// Creates a key segment.
    /// </summary>
    public static PatternSegment Key(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new PatternSegment { KeyValue = value };
    }

    /// <summary>
    /// Creates an index segment.
    /// </summary>
    public static PatternSegment Index(int value)
    {
        if(value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Index must be non-negative.");
        }

        return new PatternSegment { IndexValue = value };
    }

    /// <summary>
    /// Creates a wildcard segment.
    /// </summary>
    public static PatternSegment Wildcard() => new();

    /// <inheritdoc/>
    public override string ToString()
    {
        if(IsKey)
        {
            return $"\"{KeyValue}\"";
        }

        if(IsIndex)
        {
            return IndexValue!.Value.ToString(CultureInfo.InvariantCulture);
        }

        return "null";
    }
}