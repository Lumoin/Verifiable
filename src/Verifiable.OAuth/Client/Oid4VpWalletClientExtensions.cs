using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.Oid4Vp.Wallet;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches the default <see cref="Oid4VpWalletClient"/> sub-client to
/// <see cref="OAuthClient"/> via a Pattern 5 extension block. Applications with
/// a bespoke wallet configuration construct <see cref="Oid4VpWalletClient"/>
/// directly with the same infrastructure.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Oid4VpWalletClientExtensions
{
    extension(OAuthClient client)
    {
        /// <summary>
        /// The default OID4VP Wallet sub-client. Non-null when
        /// <see cref="OAuthClientInfrastructure.DefaultOid4VpWalletConfiguration"/>
        /// is wired; <see langword="null"/> otherwise.
        /// </summary>
        public Oid4VpWalletClient? Oid4VpWallet =>
            client.Infrastructure.DefaultOid4VpWalletConfiguration is null
                ? null
                : new Oid4VpWalletClient(
                    client.Infrastructure,
                    client.Infrastructure.DefaultOid4VpWalletConfiguration);
    }
}
