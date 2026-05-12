using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.Oid4Vp.Wallet;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Attaches the default <see cref="Oid4VpWalletClient{TCredential}"/> sub-client
/// (typed at <see cref="SdJwtVcCredential"/>) to <see cref="OAuthClient"/>
/// via a Pattern 5 extension block. Applications needing a different
/// <c>TCredential</c> construct <see cref="Oid4VpWalletClient{TCredential}"/>
/// directly with the same infrastructure.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class Oid4VpWalletClientExtensions
{
    extension(OAuthClient client)
    {
        /// <summary>
        /// The default OID4VP Wallet sub-client for SD-JWT VC presentations.
        /// Non-null when
        /// <see cref="OAuthClientInfrastructure.DefaultSdJwtVcWalletConfiguration"/>
        /// is wired; <see langword="null"/> otherwise.
        /// </summary>
        public Oid4VpWalletClient<SdJwtVcCredential>? Oid4VpWallet =>
            client.Infrastructure.DefaultSdJwtVcWalletConfiguration is null
                ? null
                : new Oid4VpWalletClient<SdJwtVcCredential>(
                    client.Infrastructure,
                    client.Infrastructure.DefaultSdJwtVcWalletConfiguration);
    }
}
