using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Verifiable.Json
{
    /// <summary>
    /// Helper methods to throw. Extracting throw makes conditional branches smaller, more inlinable and reduces
    /// generic codegen size.
    /// </summary>
    /// <remarks>Based on <see href="https://github.com/dotnet/runtime/blob/main/src/libraries/System.Text.Json/src/System/Text/Json/ThrowHelper.cs">
    /// ThrowHelper.cs</see> and <see href="https://github.com/dotnet/runtime/blob/main/src/libraries/System.Text.Json/src/System/Text/Json/ThrowHelper.Serialization.cs">
    /// ThrowHelper.Serialization.cs</see></remarks>.
    public static class JsonThrowHelper
    {
        /// <summary>
        /// Throws a JSON exception.
        /// </summary>
        [DoesNotReturn]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowJsonException()
        {
            throw new JsonException();
        }


        /// <summary>
        /// Throws a JSON exception with a message.
        /// </summary>
        /// <param name="message">The message.</param>
        [DoesNotReturn]
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowJsonException(string message)
        {
            throw new JsonException(message);
        }
    }
}