using System;

namespace Verifiable.Tpm
{
    /// <summary>
    /// Guard methods that check against unallowed values.
    /// </summary>
    public static class Guard
    {
        /// <summary>
        /// Checks <paramref name="value"/> is not <c>null</c>.
        /// </summary>
        /// <typeparam name="TType">The type of the parameter to check.</typeparam>
        /// <param name="value">The value to check.</param>
        /// <param name="parameterName">The name of the original value. This is used in potential <see cref="NullReferenceException"/>.</param>
        /// <returns>The value if it was not null.</returns>
        /// <exception cref="ArgumentNullException" />
        public static TType NotNull<TType>(TType value, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(value, parameterName);

            return value;
        }
    }
}
