using System.Collections.Concurrent;

namespace Verifiable.Core.Cryptography.Transformers
{
    /// <summary>
    /// Delegate for transforming key material from an input format to one of the preferred output formats.
    /// </summary>
    public delegate (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)
        KeyMaterialTransformerDelegate(ReadOnlyMemory<byte> inputMaterial, string inputFormat, (string Format, string KeyType)[] preferredFormats, Func<Tag> tagFactory);

    /// <summary>
    /// A registry for resolving key material transformers.
    /// </summary>
    public static class CryptoFormatTransformerRegistry
    {
        private static readonly ConcurrentDictionary<(string inputFormat, string keyType), KeyMaterialTransformerDelegate> transformers = new();

        public static void Register(
            string inputFormat,
            string keyType,
            KeyMaterialTransformerDelegate transformer)
        {
            transformers[(inputFormat.ToLowerInvariant(), keyType.ToLowerInvariant())] = transformer;
        }


        public static bool TryResolve(
            string inputFormat,
            string keyType,
            out KeyMaterialTransformerDelegate? transformer)
        {
            return transformers.TryGetValue((inputFormat.ToLowerInvariant(), keyType.ToLowerInvariant()), out transformer);
        }


        public static (ReadOnlyMemory<byte> TransformedKeyMaterial, string OutputFormat)  ResolveAndTransform(
            ReadOnlyMemory<byte> inputMaterial,
            string inputFormat,
            string keyType,
            (string Format, string KeyType)[] preferredFormats,
            Func<Tag> tagFactory)
        {
            if(!TryResolve(inputFormat, keyType, out var transformer) || transformer is null)
            {
                throw new InvalidOperationException($"No transformer registered for ({inputFormat}, {keyType}).");
            }

            return transformer(inputMaterial, inputFormat, preferredFormats, tagFactory);
        }
    }
}
