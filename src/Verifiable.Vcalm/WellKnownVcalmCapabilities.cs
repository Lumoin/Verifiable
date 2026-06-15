using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.Vcalm;

/// <summary>
/// Library-shipped <see cref="CapabilityIdentifier"/> instances for the W3C VCALM 1.0 service
/// roles. The <see cref="CapabilityIdentifier"/> TYPE lives in the neutral
/// <c>Verifiable.Server</c> host; the VALUES here are VCALM's, colocated with the VCALM endpoints
/// that consume them rather than on the neutral host's master capability class.
/// </summary>
/// <remarks>
/// Each capability is a URN of the form
/// <c>urn:verifiable:capability:vcalm:&lt;name&gt;</c>. The URN is the canonical identity used in
/// equality, hashing, and the capability set that gates which endpoint candidates enter the
/// per-request chain. Adding an entry here implies the library ships an implementation.
/// </remarks>
[DebuggerDisplay("WellKnownVcalmCapabilities")]
public static class WellKnownVcalmCapabilities
{
    /// <summary>
    /// W3C VCALM 1.0 verifier service
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §1.3 conforming verifier role, exposing the REQUIRED §3.3.1
    /// <c>POST /credentials/verify</c> and §3.3.2 <c>POST /presentations/verify</c> interfaces
    /// and the MAY §3.3.3 <c>POST /challenges</c> interface. VCALM is the W3C VC-domain HTTP API,
    /// a role-scoped service rather than an OID4VP wire flow.
    /// </summary>
    public static CapabilityIdentifier VcalmVerifier { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:verifier");

    /// <summary>
    /// W3C VCALM 1.0 issuer service
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §1.3 conforming issuer role, exposing the REQUIRED §3.2.1
    /// <c>POST /credentials/issue</c> interface and the MAY §3.2.2 <c>GET /credentials/{id}</c> and
    /// §3.2.3 <c>DELETE /credentials/{id}</c> interfaces. VCALM is the W3C VC-domain HTTP API,
    /// a role-scoped service rather than an OpenID issuance wire flow.
    /// </summary>
    public static CapabilityIdentifier VcalmIssuer { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:issuer");

    /// <summary>
    /// W3C VCALM 1.0 status service
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §1.3 conforming status role
    /// ("A conforming status service implementation MUST provide the interface described in Section
    /// C.3 Update Status."), exposing the REQUIRED §C.3 <c>POST /credentials/status</c> interface and
    /// the MAY §C.1 <c>POST /status-lists</c> and §C.2 <c>GET /status-lists/{id}</c> interfaces.
    /// Appendix C labels itself non-normative, yet §1.3 makes §C.3 a MUST for a conforming status
    /// service; §C.3 is therefore the binding conformance requirement and §C.1 / §C.2 are supporting
    /// MAYs.
    /// </summary>
    public static CapabilityIdentifier VcalmStatus { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:status");

    /// <summary>
    /// W3C VCALM 1.0 holder presentation surface
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §3.5 presenting interfaces: §3.5.1 <c>POST /credentials/derive</c>,
    /// §3.5.2 <c>POST /presentations</c>, §3.5.3 <c>GET /presentations</c>, §3.5.4
    /// <c>GET /presentations/{id}</c>, and §3.5.5 <c>DELETE /presentations/{id}</c>. §3.5 is the holder
    /// service's OPTIONAL presentation surface — the §1.3 conforming-holder MUST is §3.6.4 / §3.6.5
    /// exchange participation, not the presentation CRUD here ("the optional services and their
    /// optional API endpoints" of §1.3); this capability gates the conformant OPTIONAL §3.5
    /// implementation.
    /// </summary>
    public static CapabilityIdentifier VcalmHolder { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:holder");

    /// <summary>
    /// W3C VCALM 1.0 exchange engine
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §3.6 workflows-and-exchanges surface, gating the §3.6.3
    /// <c>POST .../exchanges</c> create-exchange interface, the §1.3 conforming-holder REQUIRED
    /// §3.6.4 <c>GET .../exchanges/{id}/protocols</c> and §3.6.5 <c>POST .../exchanges/{id}</c>
    /// vcapi-participation interfaces, and the §3.6.6 <c>GET .../exchanges/{id}</c> exchange-state
    /// interface. §1.3: "A conforming holder service implementation MUST provide the interface
    /// described in Section 3.6.4 Get Exchange Protocols and Section 3.6.5 Participate in an
    /// Exchange." (The admin-authored §3.6.1 / §3.6.2 workflow-config interfaces and the §3.6.7
    /// callbacks a conforming WORKFLOW service additionally provides are a later surface; this
    /// capability ships the exchange-instance lifecycle the holder participation MUSTs run on.)
    /// </summary>
    public static CapabilityIdentifier VcalmExchange { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:exchange");

    /// <summary>
    /// W3C VCALM 1.0 administration surface
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §3.6.1 <c>POST /workflows</c> create-workflow and §3.6.2
    /// <c>GET /workflows/{localWorkflowId}</c> get-workflow-configuration admin interfaces (§3.1: these
    /// endpoints' expected caller is "Administrators"). §1.3: "A conforming workflow service
    /// implementation MUST provide all of the interfaces described in Section 3.6 Workflows and
    /// Exchanges." — the admin-authored workflow CONFIG is the part of §3.6 the administration role
    /// owns; the exchange-instance lifecycle the holder participation MUSTs run on is
    /// <see cref="VcalmExchange"/>. The two are co-registered for a full §3.6 workflow service.
    /// </summary>
    public static CapabilityIdentifier VcalmAdministration { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:administration");

    /// <summary>
    /// W3C VCALM 1.0 coordinator interaction surface
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
    /// Management</see>) — the §3.7 "Initiating Interactions" bootstrapping layer a coordinator hosts:
    /// the §3.7.4 <c>GET</c>-interaction-URL protocols response (the content-negotiated
    /// <c>{protocols:{…}}</c> / <c>text/html</c> answer) and the §3.7.5 <c>POST</c>-inviteRequest
    /// holder-initiated protocol entry. §2.1 / §3.7.1: the interaction URL "be hosted on a coordinator
    /// and NOT hosted at the workflow service", so its Web origin (DNS domain) is a consistent trust
    /// signal — the interaction surface is therefore a COORDINATOR capability distinct from the §3.2 /
    /// §3.3 / §3.5 / §3.6 SERVICE capabilities, even when one deployment co-hosts both roles. The §3.7.6
    /// vcapi protocol entry the §3.7.4 map advertises addresses the §3.6 exchange engine
    /// (<see cref="VcalmExchange"/>); §3.7 does not re-implement the exchange, it points at it.
    /// </summary>
    public static CapabilityIdentifier VcalmCoordinator { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:vcalm:coordinator");
}
