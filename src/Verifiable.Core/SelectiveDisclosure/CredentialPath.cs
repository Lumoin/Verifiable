using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.SelectiveDisclosure;

using JsonPointerType = JsonPointer.JsonPointer;

/// <summary>
/// Represents a path to an element in a credential, supporting multiple path representations.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Path Types:</strong>
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                       CredentialPath Types                              │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │  JSON Path (SD-JWT, SD-CWT)          N-Quad Path (ECDSA-SD-2023)        │
/// │  ┌─────────────────────────┐         ┌─────────────────────────┐        │
/// │  │ /credentialSubject/name │         │ _nquad:42               │        │
/// │  │ /credentialSubject/0    │         │                         │        │
/// │  │ Hierarchical structure  │         │ Flat statement index    │        │
/// │  └─────────────────────────┘         └─────────────────────────┘        │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>JSON Paths:</strong>
/// </para>
/// <para>
/// For SD-JWT and SD-CWT, paths follow RFC 6901 JSON Pointer syntax. They support
/// hierarchical navigation including object properties and array indexes.
/// </para>
/// <para>
/// <strong>N-Quad Paths:</strong>
/// </para>
/// <para>
/// For ECDSA-SD-2023, paths reference N-Quad statement indexes. These are flat
/// references into the canonicalized RDF graph and do not preserve JSON hierarchy.
/// </para>
/// <para>
/// <strong>Design Decision:</strong>
/// </para>
/// <para>
/// This type composes <see cref="JsonPointer.JsonPointer"/> rather than
/// duplicating its functionality. For pure JSON Pointer operations without N-Quad
/// support, use <see cref="JsonPointer.JsonPointer"/> directly.
/// </para>
/// <para>
/// <strong>Thread Safety:</strong> This type is immutable and thread-safe.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly struct CredentialPath: IEquatable<CredentialPath>, IComparable<CredentialPath>
{
    private readonly JsonPointerType? jsonPointer;
    private readonly int? nquadIndex;

    /// <summary>
    /// The root path representing the credential document root.
    /// </summary>
    public static CredentialPath Root { get; } = new(JsonPointerType.Root);

    /// <summary>
    /// Whether this is a JSON-based path (can be expressed as JSON Pointer).
    /// </summary>
    public bool IsJsonPath => jsonPointer.HasValue;

    /// <summary>
    /// Whether this is an N-Quad statement path.
    /// </summary>
    public bool IsNQuadPath => nquadIndex.HasValue;

    /// <summary>
    /// Whether this is the root path.
    /// </summary>
    public bool IsRoot => IsJsonPath && jsonPointer!.Value.IsRoot;

    /// <summary>
    /// Depth in the credential tree (0 = root).
    /// </summary>
    /// <remarks>
    /// For N-Quad paths, depth is always 1 since they are flat references.
    /// </remarks>
    public int Depth => IsJsonPath ? jsonPointer!.Value.Depth : 1;

    /// <summary>
    /// The underlying JSON Pointer if this is a JSON path.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if this is an N-Quad path.</exception>
    public JsonPointerType JsonPointer
    {
        get
        {
            if(!IsJsonPath)
            {
                throw new InvalidOperationException(
                    "Cannot get JSON Pointer from an N-Quad path. Check IsJsonPath first.");
            }

            return jsonPointer!.Value;
        }
    }

    /// <summary>
    /// The N-Quad statement index if this is an N-Quad path.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if this is a JSON path.</exception>
    public int NQuadIndex
    {
        get
        {
            if(!IsNQuadPath)
            {
                throw new InvalidOperationException(
                    "Cannot get N-Quad index from a JSON path. Check IsNQuadPath first.");
            }

            return nquadIndex!.Value;
        }
    }


    /// <summary>
    /// Creates a credential path from a JSON Pointer.
    /// </summary>
    public CredentialPath(JsonPointerType pointer)
    {
        jsonPointer = pointer;
        nquadIndex = null;
    }


    private CredentialPath(int nquadIndex)
    {
        jsonPointer = null;
        this.nquadIndex = nquadIndex;
    }


    /// <summary>
    /// Creates a path from a JSON Pointer string (RFC 6901).
    /// </summary>
    /// <param name="pointer">The JSON Pointer string (e.g., "/credentialSubject/name").</param>
    /// <returns>A new credential path.</returns>
    /// <exception cref="FormatException">Thrown if the pointer format is invalid.</exception>
    public static CredentialPath FromJsonPointer(string pointer)
    {
        return new CredentialPath(JsonPointerType.Parse(pointer));
    }


    /// <summary>
    /// Attempts to parse a JSON Pointer string.
    /// </summary>
    public static bool TryFromJsonPointer(string? pointer, out CredentialPath path)
    {
        if(JsonPointerType.TryParse(pointer, out JsonPointerType result))
        {
            path = new CredentialPath(result);
            return true;
        }

        path = default;
        return false;
    }


    /// <summary>
    /// Creates a path for an N-Quad statement index.
    /// </summary>
    /// <param name="index">The statement index in canonical order.</param>
    /// <returns>A path representing the N-Quad statement.</returns>
    /// <remarks>
    /// N-Quad paths are used by ECDSA-SD-2023 which operates on canonicalized
    /// RDF statements. The index refers to the position in the sorted list
    /// of canonical N-Quads.
    /// </remarks>
    public static CredentialPath FromNQuadIndex(int index)
    {
        if(index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Index must be non-negative.");
        }

        return new CredentialPath(index);
    }


    /// <summary>
    /// Implicitly converts a JSON Pointer to a credential path.
    /// </summary>
    public static implicit operator CredentialPath(JsonPointerType pointer) => new(pointer);


    /// <summary>
    /// Converts to JSON Pointer string representation.
    /// </summary>
    /// <remarks>
    /// For N-Quad paths, returns a pseudo-pointer in the format "/_nquad:{index}".
    /// </remarks>
    public string ToJsonPointerString()
    {
        if(IsJsonPath)
        {
            return jsonPointer!.Value.ToString();
        }

        return $"/_nquad:{nquadIndex}";
    }


    /// <summary>
    /// Returns the parent path, or <c>null</c> if this is the root or an N-Quad path.
    /// </summary>
    public CredentialPath? Parent
    {
        get
        {
            if(!IsJsonPath)
            {
                return null;
            }

            JsonPointerType? parent = jsonPointer!.Value.Parent;
            return parent.HasValue ? new CredentialPath(parent.Value) : null;
        }
    }


    /// <summary>
    /// Returns all ancestor paths from root to this path (exclusive of this path).
    /// </summary>
    public IEnumerable<CredentialPath> Ancestors()
    {
        if(IsJsonPath)
        {
            foreach(JsonPointerType ancestor in jsonPointer!.Value.Ancestors())
            {
                yield return new CredentialPath(ancestor);
            }
        }
        else
        {
            yield return Root;
        }
    }


    /// <summary>
    /// Returns this path and all ancestor paths.
    /// </summary>
    public IEnumerable<CredentialPath> SelfAndAncestors()
    {
        if(IsJsonPath)
        {
            foreach(JsonPointerType ancestor in jsonPointer!.Value.SelfAndAncestors())
            {
                yield return new CredentialPath(ancestor);
            }
        }
        else
        {
            yield return Root;
            yield return this;
        }
    }


    /// <summary>
    /// Creates a child path by appending a property segment.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if this is an N-Quad path.</exception>
    public CredentialPath Append(string propertyName)
    {
        if(!IsJsonPath)
        {
            throw new InvalidOperationException("Cannot append to N-Quad path.");
        }

        return new CredentialPath(jsonPointer!.Value.Append(propertyName));
    }


    /// <summary>
    /// Creates a child path by appending an array index segment.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if this is an N-Quad path.</exception>
    public CredentialPath Append(int index)
    {
        if(!IsJsonPath)
        {
            throw new InvalidOperationException("Cannot append to N-Quad path.");
        }

        return new CredentialPath(jsonPointer!.Value.Append(index));
    }


    /// <summary>
    /// Checks if this path is an ancestor of another path.
    /// </summary>
    public bool IsAncestorOf(CredentialPath other)
    {
        if(!IsJsonPath || !other.IsJsonPath)
        {
            return false;
        }

        return jsonPointer!.Value.IsAncestorOf(other.jsonPointer!.Value);
    }


    /// <summary>
    /// Checks if this path is a descendant of another path.
    /// </summary>
    public bool IsDescendantOf(CredentialPath other) => other.IsAncestorOf(this);


    /// <summary>
    /// Checks if this path is an ancestor of or equal to another path.
    /// </summary>
    public bool IsAncestorOfOrEqualTo(CredentialPath other) => Equals(other) || IsAncestorOf(other);


    /// <summary>
    /// Checks if this path is a descendant of or equal to another path.
    /// </summary>
    public bool IsDescendantOfOrEqualTo(CredentialPath other) => other.IsAncestorOfOrEqualTo(this);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CredentialPath other)
    {
        if(IsJsonPath && other.IsJsonPath)
        {
            return jsonPointer!.Value.Equals(other.jsonPointer!.Value);
        }

        if(IsNQuadPath && other.IsNQuadPath)
        {
            return nquadIndex == other.nquadIndex;
        }

        return false;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CredentialPath other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        if(IsJsonPath)
        {
            return HashCode.Combine(1, jsonPointer!.Value);
        }

        return HashCode.Combine(2, nquadIndex);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public int CompareTo(CredentialPath other)
    {
        //JSON paths come before N-Quad paths.
        if(IsJsonPath && other.IsJsonPath)
        {
            return jsonPointer!.Value.CompareTo(other.jsonPointer!.Value);
        }

        if(IsJsonPath)
        {
            return -1;
        }

        if(other.IsJsonPath)
        {
            return 1;
        }

        return nquadIndex!.Value.CompareTo(other.nquadIndex!.Value);
    }


    /// <summary>
    /// Returns the string representation of this path.
    /// </summary>
    public override string ToString() => ToJsonPointerString();


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(CredentialPath left, CredentialPath right) => left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(CredentialPath left, CredentialPath right) => !left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator <(CredentialPath left, CredentialPath right) => left.CompareTo(right) < 0;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator <=(CredentialPath left, CredentialPath right) => left.CompareTo(right) <= 0;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator >(CredentialPath left, CredentialPath right) => left.CompareTo(right) > 0;

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator >=(CredentialPath left, CredentialPath right) => left.CompareTo(right) >= 0;
}