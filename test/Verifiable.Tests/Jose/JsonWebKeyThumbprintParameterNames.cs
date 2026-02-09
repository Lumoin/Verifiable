using System;

namespace Verifiable.Jwt
{
    /// <summary>
    /// Xyz.
    /// </summary>
    internal static class JsonWebKeyThumbprintParameterNames
    {
        public static string Crv => "crv";

        public static string D => "d";

        public static string E => "e";

        public static string K => "k";

        public static string Kty => "kty";

        public static string N => "n";

        public static string X => "x";

        public static string Y => "y";


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="Crv"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Crv"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsCrv(string jsonAttribute)
        {
            return Equals(Crv, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the  <paramref name="jsonAttribute"/> is <see cref="D"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="D"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsD(string jsonAttribute)
        {
            return Equals(D, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="E"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="E"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsE(string jsonAttribute)
        {
            return Equals(E, jsonAttribute);
        }

        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="K"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="K"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsK(string jsonAttribute)
        {
            return Equals(K, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="Kty"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Kty"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsKty(string jsonAttribute)
        {
            return Equals(Kty, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="N"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="N"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsN(string jsonAttribute)
        {
            return Equals(N, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="X"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="X"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX(string jsonAttribute)
        {
            return Equals(X, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="Y"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Y"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsY(string jsonAttribute)
        {
            return Equals(Y, jsonAttribute);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match. This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="jsonAttribute"></param>
        /// <returns>The equivalent static instance of <paramref name="jsonAttribute"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string jsonAttribute) => jsonAttribute switch
        {
            string _ when IsCrv(jsonAttribute) => Crv,
            string _ when IsD(jsonAttribute) => D,
            string _ when IsE(jsonAttribute) => E,
            string _ when IsK(jsonAttribute) => K,
            string _ when IsKty(jsonAttribute) => Kty,
            string _ when IsN(jsonAttribute) => N,
            string _ when IsX(jsonAttribute) => X,
            string _ when IsY(jsonAttribute) => Y,
            string _ => jsonAttribute
        };


        /// <summary>
        /// Returns a value that indicates if the Crypto Suites are the same.
        /// </summary>
        /// <param name="jsonAttributeA">The first JSON attribute to compare.</param>
        /// <param name="jsonAttributeB">The first JSON attribute to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the attributes are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string jsonAttributeA, string jsonAttributeB)
        {
            return object.ReferenceEquals(jsonAttributeA, jsonAttributeB) || StringComparer.OrdinalIgnoreCase.Equals(jsonAttributeA, jsonAttributeB);
        }
    }
}
