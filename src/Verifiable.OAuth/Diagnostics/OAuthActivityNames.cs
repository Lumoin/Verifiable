using Verifiable.Cryptography.Text;


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
    /// <summary>The UTF-8 source literal of <see cref="Handle"/>.</summary>
    public static ReadOnlySpan<byte> HandleUtf8 => "oauth.server.handle"u8;

    /// <summary>
    /// The top-level span for <see cref="Server.AuthorizationServer.HandleAsync"/>.
    /// Covers the full request lifecycle: correlation resolution, state load,
    /// input building, PDA step, response building, and state save.
    /// </summary>
    public static readonly string Handle = Utf8Constants.ToInternedString(HandleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResolveCorrelation"/>.</summary>
    public static ReadOnlySpan<byte> ResolveCorrelationUtf8 => "oauth.server.resolve_correlation"u8;

    /// <summary>
    /// Resolving an external correlation handle to the internal flow identifier.
    /// </summary>
    public static readonly string ResolveCorrelation = Utf8Constants.ToInternedString(ResolveCorrelationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LoadFlowState"/>.</summary>
    public static ReadOnlySpan<byte> LoadFlowStateUtf8 => "oauth.server.load_flow_state"u8;

    /// <summary>
    /// Loading persisted flow state from the application's store.
    /// </summary>
    public static readonly string LoadFlowState = Utf8Constants.ToInternedString(LoadFlowStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BuildInput"/>.</summary>
    public static ReadOnlySpan<byte> BuildInputUtf8 => "oauth.server.build_input"u8;

    /// <summary>
    /// Building the flow input from request fields and context.
    /// Includes validation checks.
    /// </summary>
    public static readonly string BuildInput = Utf8Constants.ToInternedString(BuildInputUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StepPda"/>.</summary>
    public static ReadOnlySpan<byte> StepPdaUtf8 => "oauth.server.step_pda"u8;

    /// <summary>
    /// Stepping the PDA and executing the effectful action loop.
    /// </summary>
    public static readonly string StepPda = Utf8Constants.ToInternedString(StepPdaUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SaveFlowState"/>.</summary>
    public static ReadOnlySpan<byte> SaveFlowStateUtf8 => "oauth.server.save_flow_state"u8;

    /// <summary>
    /// Saving the updated flow state to the application's store.
    /// </summary>
    public static readonly string SaveFlowState = Utf8Constants.ToInternedString(SaveFlowStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="BuildJwks"/>.</summary>
    public static ReadOnlySpan<byte> BuildJwksUtf8 => "oauth.server.build_jwks"u8;

    /// <summary>
    /// Building the JWKS document from the key store.
    /// </summary>
    public static readonly string BuildJwks = Utf8Constants.ToInternedString(BuildJwksUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SignToken"/>.</summary>
    public static ReadOnlySpan<byte> SignTokenUtf8 => "oauth.server.sign_token"u8;

    /// <summary>
    /// Signing a JWT (access token, ID token, JAR).
    /// </summary>
    public static readonly string SignToken = Utf8Constants.ToInternedString(SignTokenUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientLifecycle"/>.</summary>
    public static ReadOnlySpan<byte> ClientLifecycleUtf8 => "oauth.server.client_lifecycle"u8;

    /// <summary>
    /// Client registration lifecycle operation.
    /// </summary>
    public static readonly string ClientLifecycle = Utf8Constants.ToInternedString(ClientLifecycleUtf8);
}
