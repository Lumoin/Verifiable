namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Activity (span) names for OAuth authorization server operations.
/// </summary>
/// <remarks>
/// <para>
/// Names follow the OTel semantic convention pattern: <c>{domain}.{operation}</c>.
/// Each name corresponds to one logical operation boundary in the server.
/// </para>
/// </remarks>
public static class OAuthActivityNames
{
    /// <summary>
    /// The top-level span for <see cref="Server.AuthorizationServer.HandleAsync"/>.
    /// Covers the full request lifecycle: correlation resolution, state load,
    /// input building, PDA step, response building, and state save.
    /// </summary>
    public static readonly string Handle = "oauth.server.handle";

    /// <summary>
    /// Resolving an external correlation handle to the internal flow identifier.
    /// </summary>
    public static readonly string ResolveCorrelation = "oauth.server.resolve_correlation";

    /// <summary>
    /// Loading persisted flow state from the application's store.
    /// </summary>
    public static readonly string LoadFlowState = "oauth.server.load_flow_state";

    /// <summary>
    /// Building the flow input from request fields and context.
    /// Includes validation checks.
    /// </summary>
    public static readonly string BuildInput = "oauth.server.build_input";

    /// <summary>
    /// Stepping the PDA and executing the effectful action loop.
    /// </summary>
    public static readonly string StepPda = "oauth.server.step_pda";

    /// <summary>
    /// Saving the updated flow state to the application's store.
    /// </summary>
    public static readonly string SaveFlowState = "oauth.server.save_flow_state";

    /// <summary>
    /// Building the JWKS document from the key store.
    /// </summary>
    public static readonly string BuildJwks = "oauth.server.build_jwks";

    /// <summary>
    /// Signing a JWT (access token, ID token, JAR).
    /// </summary>
    public static readonly string SignToken = "oauth.server.sign_token";

    /// <summary>
    /// Client registration lifecycle operation.
    /// </summary>
    public static readonly string ClientLifecycle = "oauth.server.client_lifecycle";
}
