using System;
using Verifiable.Core.Model.Did.Methods;

namespace Verifiable.Tests.Resolver
{
    public static class WebDidResolver
    {
        private static char[] Separator { get; } = [':'];

        public static string Resolve(string didWebIdentifier)
        {
            if(!didWebIdentifier.StartsWith(WebDidMethod.Prefix))
            {
                throw new ArgumentException($"The given DID identifier '{didWebIdentifier}' is not a valid DID Web identifier.");
            }

            var parts = didWebIdentifier[WebDidMethod.Prefix.Length..].Split(Separator);
            var domainAndPath = string.Join('/', parts);
            domainAndPath = Uri.UnescapeDataString(domainAndPath);

            var httpsUrl = $"https://{domainAndPath}";

            if(!domainAndPath.Contains('/', StringComparison.InvariantCulture))
            {
                httpsUrl += "/.well-known";
            }

            httpsUrl += "/did.json";
            return httpsUrl;
        }
    }
}
