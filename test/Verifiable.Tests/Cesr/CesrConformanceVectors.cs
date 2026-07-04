using System.Collections.Generic;
using System.IO;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// A single parsed CESR conformance vector: a code together with its three domain representations (raw,
/// binary, and text), and the index/ondex for indexed primitives.
/// </summary>
/// <param name="Code">The stable code, for example <c>0B</c>.</param>
/// <param name="Raw">The raw value bytes.</param>
/// <param name="Binary">The binary domain (qb2) bytes.</param>
/// <param name="Text">The text domain (qb64) characters.</param>
/// <param name="Index">The signature index for an indexed primitive, otherwise <see langword="null"/>.</param>
/// <param name="Ondex">The other-index for a dual-indexed primitive, otherwise <see langword="null"/>.</param>
/// <param name="Name">The file name the vector came from, for diagnostics.</param>
internal sealed record CesrConformanceVector(string Code, byte[] Raw, byte[] Binary, string Text, int? Index, int? Ondex, string Name, bool Malformed);


/// <summary>
/// Locates and parses the external CESR conformance vector corpus. The corpus is an independently produced
/// oracle (the reference vectors for the CESR specification); it is not committed to this repository, so the
/// corpus-driven tests are gated on its presence and skip when it is absent (for example in continuous
/// integration), in the same way the hardware-gated tests skip when their device is unavailable.
/// </summary>
/// <remarks>
/// The corpus root is supplied through the <c>VERIFIABLE_CESR_VECTOR_CORPUS</c> environment variable and is
/// expected to contain <c>test_vectors/primitives</c> and <c>test_vectors/indexes</c> directories. Each file
/// is a simple key/value record with <c>code</c>, <c>raw</c>, <c>qb2</c>, and <c>qb64</c> entries (and
/// <c>index</c>/<c>ondex</c> for indexed primitives), where <c>raw</c> and <c>qb2</c> are dash-separated
/// hexadecimal byte sequences.
/// </remarks>
internal static class CesrConformanceVectors
{
    /// <summary>
    /// The environment variable naming the corpus root directory.
    /// </summary>
    public const string CorpusVariable = "VERIFIABLE_CESR_VECTOR_CORPUS";


    /// <summary>
    /// Attempts to resolve the corpus root directory.
    /// </summary>
    /// <param name="root">The resolved corpus root when present.</param>
    /// <returns><see langword="true"/> when the corpus is available; otherwise <see langword="false"/>.</returns>
    public static bool TryGetCorpusRoot(out string root)
    {
        string? configured = Environment.GetEnvironmentVariable(CorpusVariable);
        if(!string.IsNullOrWhiteSpace(configured) && Directory.Exists(configured))
        {
            root = configured;
            return true;
        }

        root = string.Empty;
        return false;
    }


    /// <summary>
    /// Enumerates the parsed primitive vectors from the corpus.
    /// </summary>
    /// <param name="root">The corpus root directory.</param>
    /// <returns>The parsed primitive vectors.</returns>
    public static IEnumerable<CesrConformanceVector> EnumeratePrimitives(string root) =>
        EnumerateDirectory(Path.Combine(root, "test_vectors", "primitives"));


    /// <summary>
    /// Enumerates the parsed indexed vectors from the corpus.
    /// </summary>
    /// <param name="root">The corpus root directory.</param>
    /// <returns>The parsed indexed vectors.</returns>
    public static IEnumerable<CesrConformanceVector> EnumerateIndexes(string root) =>
        EnumerateDirectory(Path.Combine(root, "test_vectors", "indexes"));


    private static IEnumerable<CesrConformanceVector> EnumerateDirectory(string directory)
    {
        if(!Directory.Exists(directory))
        {
            yield break;
        }

        foreach(string file in Directory.EnumerateFiles(directory))
        {
            yield return Parse(file);
        }
    }


    private static CesrConformanceVector Parse(string file)
    {
        string code = string.Empty;
        byte[] raw = [];
        byte[] binary = [];
        string text = string.Empty;
        int? index = null;
        int? ondex = null;
        bool malformed = false;
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach(string line in File.ReadLines(file))
        {
            int separator = line.IndexOf('=', StringComparison.Ordinal);
            if(separator < 0)
            {
                continue;
            }

            string key = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();

            //A few corpus files are malformed: two records concatenated, so a key appears twice. Flag those
            //and let the test skip them rather than asserting against ambiguous data.
            if(!seen.Add(key))
            {
                malformed = true;
            }

            switch(key)
            {
                case "code":
                    code = value;
                    break;
                case "raw":
                    raw = ParseHex(value);
                    break;
                case "qb2":
                    binary = ParseHex(value);
                    break;
                case "qb64":
                    text = value;
                    break;
                case "index":
                    index = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
                    break;
                case "ondex" when value != "None":
                    ondex = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
                    break;
                default:
                    break;
            }
        }

        return new CesrConformanceVector(code, raw, binary, text, index, ondex, Path.GetFileName(file), malformed);
    }


    private static byte[] ParseHex(string value)
    {
        if(string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return Convert.FromHexString(value.Replace("-", string.Empty, StringComparison.Ordinal));
    }
}
