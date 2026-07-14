using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Cryptography.Cbom;

namespace Verifiable;

/// <summary>
/// Serializes a <see cref="CbomDocument"/> to spec-exact CycloneDX 1.6 JSON.
/// </summary>
/// <remarks>
/// <para>
/// Serialization runs through the source-generated <see cref="CbomJsonContext"/>
/// (camelCase, AOT-safe). CycloneDX requires two keys that a camelCase naming policy
/// cannot produce from a C# identifier — <c>bom-ref</c> (hyphen) and <c>$schema</c>
/// (leading <c>$</c>) — so this renderer rewrites the serialized
/// <see cref="JsonNode"/> tree: every <c>bomRef</c> key becomes <c>bom-ref</c> and the
/// document gains a leading <c>$schema</c>. The node APIs used here are
/// reflection-free and AOT-safe.
/// </para>
/// </remarks>
internal static class CbomJsonRenderer
{
    private const string CycloneDxSchema = "http://cyclonedx.org/schema/bom-1.6.schema.json";


    /// <summary>
    /// Renders the document to indented CycloneDX 1.6 JSON.
    /// </summary>
    /// <param name="document">The CBOM document.</param>
    /// <returns>The serialized JSON.</returns>
    public static string Render(CbomDocument document)
    {
        string raw = JsonSerializer.Serialize(document, CbomJsonContext.Default.CbomDocument);

        JsonNode root = JsonNode.Parse(raw)!;
        RewriteBomRefKeys(root);

        //Re-assemble with $schema first so the output reads as canonical CycloneDX.
        JsonObject ordered = new()
        {
            ["$schema"] = CycloneDxSchema
        };

        foreach(var property in root.AsObject())
        {
            ordered[property.Key] = property.Value?.DeepClone();
        }

        return ordered.ToJsonString(IndentedOptions);
    }


    private static JsonSerializerOptions IndentedOptions { get; } = new() { WriteIndented = true };


    //Recursively renames the camelCase 'bomRef' key to the CycloneDX 'bom-ref' key.
    private static void RewriteBomRefKeys(JsonNode? node)
    {
        _ = node switch
        {
            JsonObject obj => RewriteObjectArm(obj),
            JsonArray array => RewriteArrayArm(array),
            _ => 0
        };

        return;

        static int RewriteObjectArm(JsonObject obj)
        {
            if(obj.ContainsKey("bomRef"))
            {
                JsonNode? value = obj["bomRef"]?.DeepClone();
                obj.Remove("bomRef");
                obj["bom-ref"] = value;
            }

            foreach(var property in obj)
            {
                RewriteBomRefKeys(property.Value);
            }

            return 0;
        }

        static int RewriteArrayArm(JsonArray array)
        {
            foreach(JsonNode? item in array)
            {
                RewriteBomRefKeys(item);
            }

            return 0;
        }
    }
}