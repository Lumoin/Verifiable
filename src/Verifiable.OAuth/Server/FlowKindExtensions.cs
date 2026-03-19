using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Wallet;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Discoverable accessors for library-provided <see cref="FlowKind"/> singletons.
/// </summary>
/// <remarks>
/// <para>
/// Each property returns the single instance of a concrete
/// <see cref="StatefulFlowKind"/> or the <see cref="StatelessFlowKind"/>. The
/// <c>extension</c> block surfaces all accessors on the <see cref="FlowKind"/>
/// base type, so consumers write <c>FlowKind.AuthCodeServer</c> rather than
/// <c>AuthCodeServerFlowKind.Instance</c>.
/// </para>
/// <para>
/// Library users add their own flow kinds by writing a new concrete class and
/// their own <c>extension</c> block on <see cref="FlowKind"/>. The custom kinds
/// appear alongside the library-provided ones in IntelliSense:
/// </para>
/// <code>
/// public static class MyFlowKindExtensions
/// {
///     extension(FlowKind)
///     {
///         public static MyCustomFlowKind MyCustom =&gt; MyCustomFlowKind.Instance;
///     }
/// }
/// </code>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FlowKindExtensions
{
    extension(FlowKind)
    {
        /// <summary>
        /// The client-side Authorization Code flow per RFC 6749 §4.1 with PAR
        /// and PKCE.
        /// </summary>
        public static AuthCodeClientFlowKind AuthCodeClient =>
            AuthCodeClientFlowKind.Instance;


        /// <summary>
        /// The server-side Authorization Code flow per RFC 6749 §4.1 with PAR
        /// and PKCE.
        /// </summary>
        public static AuthCodeServerFlowKind AuthCodeServer =>
            AuthCodeServerFlowKind.Instance;


        /// <summary>
        /// The OID4VP verifier-side flow per OID4VP 1.0 and HAIP 1.0.
        /// </summary>
        public static Oid4VpVerifierFlowKind Oid4VpVerifier =>
            Oid4VpVerifierFlowKind.Instance;


        /// <summary>
        /// The OID4VP server-side verifier flow. Models the Verifier's HTTP
        /// endpoints: PAR, JAR serving, and direct_post response receipt.
        /// </summary>
        public static Oid4VpVerifierServerFlowKind Oid4VpVerifierServer =>
            Oid4VpVerifierServerFlowKind.Instance;


        /// <summary>
        /// The OID4VP wallet-side flow.
        /// </summary>
        public static WalletFlowKind Wallet =>
            WalletFlowKind.Instance;


        /// <summary>
        /// Marker for stateless endpoints — JWKS, discovery, and similar
        /// metadata endpoints that compute responses without any flow state.
        /// </summary>
        public static StatelessFlowKind Stateless =>
            StatelessFlowKind.Instance;
    }
}
