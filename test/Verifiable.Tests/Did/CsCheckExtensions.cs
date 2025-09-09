using CsCheck;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Extension methods for CsCheck generators to enable property-based testing.
    /// </summary>
    public static class CsCheckExtensions
    {
        /// <summary>
        /// Extension method to enable property-based testing with CsCheck.
        /// Executes a property test for all generated values.
        /// </summary>
        /// <typeparam name="T">The type of values generated.</typeparam>
        /// <param name="gen">The generator to test.</param>
        /// <param name="property">The property function that should return true for all generated values.</param>
        public static void ForAll<T>(this Gen<T> gen, Func<T, bool> property)
        {
            Check.Sample(gen, property);
        }
    }
}
