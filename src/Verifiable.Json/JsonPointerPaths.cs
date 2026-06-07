using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Json;

/// <summary>
/// Enumerates every RFC 6901 JSON-Pointer path present in a <see cref="JsonElement"/> as
/// <see cref="CredentialPath"/> values.
/// </summary>
/// <remarks>
/// <para>
/// This is the general, redaction-agnostic counterpart to the SD-JWT-specific path walk in
/// <c>SdJwtPathExtraction</c> (whose recursion is private and treats <c>_sd</c> redaction
/// markers specially). It is used to derive the full claim surface of a serialized document —
/// for example a Verifiable Credential — so the selective-disclosure engine can compute a
/// minimal disclosure against the complete set of available paths.
/// </para>
/// <para>
/// Both branch paths (objects and arrays) and leaf paths are emitted (e.g. <c>/issuer</c>,
/// <c>/credentialSubject/degree</c>, <c>/credentialSubject/degree/name</c>, <c>/type/0</c>);
/// the document root itself is not emitted. The walk is format- and query-neutral: it depends
/// only on JSON structure, not on any presentation protocol.
/// </para>
/// </remarks>
public static class JsonPointerPaths
{
    /// <summary>
    /// Enumerates all JSON-Pointer paths in <paramref name="root"/> (excluding the root path).
    /// </summary>
    /// <param name="root">The document element to walk.</param>
    /// <returns>The set of every branch and leaf path present in the element.</returns>
    public static IReadOnlySet<CredentialPath> EnumerateAll(JsonElement root)
    {
        var paths = new HashSet<CredentialPath>();
        Collect(root, CredentialPath.Root, paths);

        return paths;
    }


    private static void Collect(JsonElement element, CredentialPath path, HashSet<CredentialPath> paths)
    {
        switch(element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                foreach(JsonProperty property in element.EnumerateObject())
                {
                    var childPath = path.Append(property.Name);
                    paths.Add(childPath);
                    Collect(property.Value, childPath, paths);
                }

                break;
            }
            case JsonValueKind.Array:
            {
                int index = 0;
                foreach(JsonElement item in element.EnumerateArray())
                {
                    var childPath = path.Append(index);
                    paths.Add(childPath);
                    Collect(item, childPath, paths);
                    ++index;
                }

                break;
            }
            default:
            {
                //Leaf value: its path was already added by the enclosing object/array.
                break;
            }
        }
    }
}
