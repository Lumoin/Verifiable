namespace Verifiable.Fido2.Ctap;

/// <summary>
/// CTAP2 status codes: the leading byte of every CTAP2 response envelope, transport-agnostic (this
/// is distinct from any transport binding's own outer status word, such as the NFC binding's
/// ISO/IEC 7816-4 status word).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
/// CTAP 2.3, section 8.2: Status codes</see>. Wave 2 adds the codes
/// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s no-PIN/no-UV processing
/// paths can reach. Wave-5b adds the seven codes the <c>authenticatorClientPIN</c> PIN-path
/// subcommands (<c>setPIN</c>/<c>changePIN</c>/<c>getPinToken</c>/
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>) reach — <see cref="PinInvalid"/>,
/// <see cref="PinBlocked"/>, <see cref="PinAuthInvalid"/>, <see cref="PinAuthBlocked"/>,
/// <see cref="PinNotSet"/>, <see cref="PinPolicyViolation"/>, <see cref="UnauthorizedPermission"/>.
/// Wave-5c adds <see cref="PuatRequired"/>, returned when a pinUvAuthToken is required for an
/// operation the platform requested without presenting one. Wave-5d adds
/// <see cref="InvalidSubcommand"/>, returned when a request names a subCommand this authenticator
/// does not implement — both <c>authenticatorClientPIN</c>'s and <c>authenticatorConfig</c>'s own
/// unsupported-subCommand fallthroughs return it. The wavebio program adds
/// <see cref="InvalidLength"/> (<c>authenticatorBioEnrollment</c>'s <c>setFriendlyName</c> length
/// check), <see cref="FpDatabaseFull"/> (<c>enrollBegin</c>/<c>enrollCaptureNextSample</c> storage
/// exhaustion), <see cref="OperationDenied"/>/<see cref="UserActionTimeout"/>/<see cref="UvBlocked"/>/
/// <see cref="UvInvalid"/> (the built-in-UV cluster's <c>getPinUvAuthTokenUsingUvWithPermissions</c>
/// and <c>performBuiltInUv</c> error ladder). The wavelb program adds <see cref="InvalidSeq"/>
/// (<c>authenticatorLargeBlobs</c>' fragment-sequencing check), <see cref="LargeBlobStorageFull"/>
/// (the serialized large-blob array's capacity check), and <see cref="IntegrityFailure"/> (the
/// commit-time trailing-hash check) — all three hex-verified directly against §8's own registry rows.
/// The §9-close program adds <see cref="CborUnexpectedType"/>/<see cref="InvalidCbor"/>, realizing the
/// decode-boundary precision fix (R7): every body-carrying command boundary in
/// <c>CtapAuthenticatorSimulator.TransceiveAsync</c> classifies a decode failure via
/// <see cref="Fido2FormatException.FailureKind"/> rather than either letting it escape uncaught or
/// collapsing it onto <see cref="MissingParameter"/> regardless of cause. The remaining rows of the
/// full table (enterprise attestation, extension, vendor-specific) stay unregistered until a command
/// that can produce them ships.
/// </remarks>
public static class WellKnownCtapStatusCodes
{
    /// <summary>
    /// <c>CTAP1_ERR_SUCCESS</c>/<c>CTAP2_OK</c> (<c>0x00</c>): the command succeeded.
    /// </summary>
    public const byte Ok = 0x00;

    /// <summary>
    /// <c>CTAP1_ERR_INVALID_COMMAND</c> (<c>0x01</c>): the command byte is not a command the
    /// authenticator implements, or the request envelope was empty (no command byte at all).
    /// </summary>
    public const byte InvalidCommand = 0x01;

    /// <summary>
    /// <c>CTAP1_ERR_INVALID_PARAMETER</c> (<c>0x02</c>): the command included an invalid
    /// parameter — this wave's authenticator returns it when <c>pinUvAuthParam</c> is present
    /// together with a <c>pinUvAuthProtocol</c> value (unsupported, since no protocol is
    /// advertised in <c>authenticatorGetInfo</c>), when <c>enterpriseAttestation</c> is present
    /// against an authenticator that is not enterprise attestation capable OR is capable but
    /// currently disabled (mc Step 9 sub-step 1, CTAP 2.3 line 3331, waveep R5 — checked STRICTLY
    /// BEFORE the parameter's own value is validated, so this fires regardless of the value supplied),
    /// and when <c>authenticatorClientPIN</c>'s <c>pinUvAuthProtocol</c> names an unsupported PIN/UV auth
    /// protocol.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// CTAP 2.3, section 6.1: authenticatorMakeCredential</see> and
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
    /// section 6.2: authenticatorGetAssertion</see>'s shared <c>pinUvAuthProtocol</c>-value-unsupported
    /// step. <c>authenticatorClientPIN</c>'s own unsupported-<c>subCommand</c> fallthrough returns
    /// <see cref="InvalidSubcommand"/> instead (see that member's remarks for the R1 ruling).
    /// </remarks>
    public const byte InvalidParameter = 0x02;

    /// <summary>
    /// <c>CTAP1_ERR_INVALID_LENGTH</c> (<c>0x03</c>): "Invalid message or item length." This
    /// authenticator's producers are: <c>authenticatorBioEnrollment</c>'s <c>setFriendlyName</c>
    /// subcommand — a <c>templateFriendlyName</c> exceeding
    /// <c>CtapAuthenticatorState.MaxTemplateFriendlyNameByteLength</c> (the spec's own text, snapshot
    /// line 6880, reads "return an error e.g., CTAP1_ERR_INVALID_LENGTH," an EXAMPLE, not a mandated
    /// exact code; this profile adopts the example as its documented choice) — and
    /// <c>authenticatorLargeBlobs</c>' <c>get</c>/<c>set</c> fragment-length checks: <c>get</c>'s value
    /// exceeding <c>CtapAuthenticatorState.MaxFragmentLength</c> (line 7603) or <c>set</c>'s fragment
    /// contents exceeding it (line 7613) — this one IS a spec-named exact code, not an example.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte InvalidLength = 0x03;

    /// <summary>
    /// <c>CTAP1_ERR_INVALID_SEQ</c> (<c>0x04</c>): "Invalid message sequencing." Returned by
    /// <c>authenticatorLargeBlobs</c>' <c>set</c> when a continuation fragment's <c>offset</c> does not
    /// equal the volatile <c>expectedNextOffset</c> counter (line 7635) — the sole producer in this
    /// profile.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>, lines 8865-8867.
    /// </remarks>
    public const byte InvalidSeq = 0x04;

    /// <summary>
    /// <c>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</c> (<c>0x11</c>): "Invalid/unexpected CBOR error." The
    /// decode-boundary classification (R7) returns this when a request's CBOR is well-formed but a
    /// nested or extension-map structure is missing a required member or carries a member of the
    /// wrong CBOR type — for example, an <c>rp</c>/<c>user</c> entity without its required <c>id</c>,
    /// or a known extension key (<c>hmac-secret</c>) whose value is not a boolean.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
    /// CTAP 2.3, section 8: Message Encoding</see>, lines 8777-8783's SHOULD. See
    /// <see cref="Fido2FormatFailureKind.UnexpectedStructure"/> for the classification this maps from.
    /// </remarks>
    public const byte CborUnexpectedType = 0x11;

    /// <summary>
    /// <c>CTAP2_ERR_INVALID_CBOR</c> (<c>0x12</c>): "Error when parsing CBOR." The decode-boundary
    /// classification (R7) returns this when a request's bytes do not conform to CTAP2 canonical CBOR
    /// at all — a syntax error, a truncated buffer, a tagged value, a non-canonical integer or length
    /// encoding, or a duplicate map key.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
    /// CTAP 2.3, section 8: Message Encoding</see>, lines 8775-8776's SHOULD. See
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/> for the classification this maps from.
    /// </remarks>
    public const byte InvalidCbor = 0x12;

    /// <summary>
    /// <c>CTAP2_ERR_MISSING_PARAMETER</c> (<c>0x14</c>): a non-optional parameter is missing —
    /// this wave's authenticator returns it when <c>pinUvAuthParam</c> is present but
    /// <c>pinUvAuthProtocol</c> is absent, when <c>authenticatorClientPIN</c>'s
    /// <c>getKeyAgreement</c> subcommand is requested without the <c>pinUvAuthProtocol</c>
    /// parameter its protocol selection needs, and — via the decode-boundary classification (R7) —
    /// whenever a Required top-level command parameter (<c>authenticatorMakeCredential</c>'s
    /// <c>clientDataHash</c>, <c>authenticatorGetAssertion</c>'s <c>rpId</c>,
    /// <c>authenticatorClientPIN</c>/<c>authenticatorConfig</c>/<c>authenticatorCredentialManagement</c>'s
    /// <c>subCommand</c>) is absent from an otherwise well-formed request map.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>. <c>authenticatorConfig</c>'s own section 6.11 also
    /// names this by MUST at snapshot line 7953 for its own <c>subCommand</c> member. See
    /// <see cref="Fido2FormatFailureKind.MissingRequiredParameter"/> for the classification this maps
    /// from.
    /// </remarks>
    public const byte MissingParameter = 0x14;

    /// <summary>
    /// <c>CTAP2_ERR_CREDENTIAL_EXCLUDED</c> (<c>0x19</c>): a valid credential was found in the
    /// <c>excludeList</c> during <c>authenticatorMakeCredential</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// CTAP 2.3, section 6.1: authenticatorMakeCredential</see>, the <c>excludeList</c> processing step.
    /// </remarks>
    public const byte CredentialExcluded = 0x19;

    /// <summary>
    /// <c>CTAP2_ERR_FP_DATABASE_FULL</c> (<c>0x17</c>): "Fingerprint data base is full, e.g., during
    /// enrollment." Returned by <c>enrollBegin</c>/<c>enrollCaptureNextSample</c> when the fingerprint
    /// template store has no space for a new enrollment (<c>CtapAuthenticatorState.MaxEnrolledTemplatesCapacity</c>).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte FpDatabaseFull = 0x17;

    /// <summary>
    /// <c>CTAP2_ERR_LARGE_BLOB_STORAGE_FULL</c> (<c>0x18</c>): "Large blob storage is full." Returned by
    /// <c>authenticatorLargeBlobs</c>' <c>set</c>, offset zero, when the requested <c>length</c> exceeds
    /// 1024 bytes AND exceeds <c>CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity</c> (line
    /// 7620) — the same capacity <c>authenticatorGetInfo</c>'s <c>maxSerializedLargeBlobArray</c> member
    /// advertises, single-sourced.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>, lines 8905-8907.
    /// </remarks>
    public const byte LargeBlobStorageFull = 0x18;

    /// <summary>
    /// <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c> (<c>0x26</c>): none of the algorithms named in
    /// <c>pubKeyCredParams</c> is supported.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// CTAP 2.3, section 6.1: authenticatorMakeCredential</see>, the <c>pubKeyCredParams</c> processing step.
    /// </remarks>
    public const byte UnsupportedAlgorithm = 0x26;

    /// <summary>
    /// <c>CTAP2_ERR_OPERATION_DENIED</c> (<c>0x27</c>): "Not authorized for requested operation." The
    /// built-in-UV cluster's own display-consent decline (a documented no-op — no display is modeled),
    /// the <c>mc</c>/<c>ga</c> <c>options.uv</c> error ladder's fallback disposition, and
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s own step 8 consent-decline slot.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte OperationDenied = 0x27;

    /// <summary>
    /// <c>CTAP2_ERR_KEY_STORE_FULL</c> (<c>0x28</c>): the authenticator does not have enough
    /// internal storage to persist the new resident credential — this wave's authenticator returns
    /// it when a resident <c>authenticatorMakeCredential</c> request would grow the resident-credential
    /// store past its configured capacity (a simulator-realism knob, not a spec-mandated number — the
    /// spec only requires SOME finite capacity to exist, per
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// section 6.1</see>'s discoverable-credential step). A same-(<c>rp.id</c>, account) registration
    /// always overwrites the existing credential instead, unconditionally, and never counts against
    /// capacity.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
    /// CTAP 2.3, section 6.1: authenticatorMakeCredential</see>, "If authenticator does not have
    /// enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL."
    /// </remarks>
    public const byte KeyStoreFull = 0x28;

    /// <summary>
    /// <c>CTAP2_ERR_UNSUPPORTED_OPTION</c> (<c>0x2B</c>): an option key the request sent is not
    /// supported for the current operation — this wave's authenticator returns it for
    /// <c>options.rk</c> on <c>authenticatorMakeCredential</c> when <c>authenticatorGetInfo</c>
    /// does not advertise the <c>rk</c> option ID, and unconditionally for <c>options.rk</c> on
    /// <c>authenticatorGetAssertion</c> (the platform must never send it there at all).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte UnsupportedOption = 0x2B;

    /// <summary>
    /// <c>CTAP2_ERR_INVALID_OPTION</c> (<c>0x2C</c>): an option's value is not valid for the
    /// current operation — this authenticator returns it for <c>options.uv = true</c> when the built-in
    /// user verification method is not yet configured (zero fingerprint enrollments) on both mc and ga
    /// (CTAP 2.3 lines 3213/3901 — distinct from <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s own
    /// <c>CTAP2_ERR_NOT_ALLOWED</c> for the identical underlying state, uv scout trap 7), for
    /// <c>options.up = false</c> on <c>authenticatorMakeCredential</c>, for <c>enumerateEnrollments</c>
    /// with zero enrollments/an unknown <c>templateId</c>, and for mc Step 9 sub-step 2.1 (CTAP 2.3 line
    /// 3336, waveep R5): <c>enterpriseAttestation</c> present with a value that is neither 1 nor 2, on an
    /// authenticator that IS enterprise attestation capable and enabled (a capable-but-disabled or
    /// non-capable authenticator never reaches this check — see <see cref="InvalidParameter"/>).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte InvalidOption = 0x2C;

    /// <summary>
    /// <c>CTAP2_ERR_NO_CREDENTIALS</c> (<c>0x2E</c>): no credential matched the assertion request
    /// (the resolved applicable-credentials list is empty).
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
    /// CTAP 2.3, section 6.2: authenticatorGetAssertion</see>, the locate-credentials processing step.
    /// </remarks>
    public const byte NoCredentials = 0x2E;

    /// <summary>
    /// <c>CTAP2_ERR_USER_ACTION_TIMEOUT</c> (<c>0x2F</c>): a user action timeout occurred. Returned by
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c> and the <c>mc</c>/<c>ga</c> <c>options.uv</c>
    /// error ladder when <c>performBuiltInUv</c>'s own outcome is a timeout.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte UserActionTimeout = 0x2F;

    /// <summary>
    /// <c>CTAP2_ERR_NOT_ALLOWED</c> (<c>0x30</c>): "Continuation command, such as,
    /// authenticatorGetNextAssertion not allowed." This wave's authenticator returns it for every
    /// <c>authenticatorGetNextAssertion</c> error path: no remembered <c>authenticatorGetAssertion</c>
    /// sequence, the sequence already exhausted, or its 30-second timer expired. <c>authenticatorReset</c>
    /// reuses the identical byte for an unrelated, second meaning of its own: "If the request comes
    /// after 10 seconds of powering up, the authenticator returns CTAP2_ERR_NOT_ALLOWED" — that
    /// disposition comes from section 6.6's own paragraph, not from the generic status-table row's
    /// continuation-command wording quoted above.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
    /// CTAP 2.3, section 6.3: authenticatorGetNextAssertion</see>. Also
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset">
    /// CTAP 2.3, section 6.6: authenticatorReset (0x07)</see>, line 6374.
    /// </remarks>
    public const byte NotAllowed = 0x30;

    /// <summary>
    /// <c>CTAP2_ERR_PIN_INVALID</c> (<c>0x31</c>): "PIN Invalid" — the PIN presented did not match
    /// <c>CurrentStoredPIN</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PinInvalid = 0x31;

    /// <summary>
    /// <c>CTAP2_ERR_PIN_BLOCKED</c> (<c>0x32</c>): "PIN Blocked" — the <c>pinRetries</c> counter has
    /// reached 0; <c>clientPIN</c> is permanently disabled until the authenticator is reset.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PinBlocked = 0x32;

    /// <summary>
    /// <c>CTAP2_ERR_PIN_AUTH_INVALID</c> (<c>0x33</c>): "PIN authentication, pinUvAuthParam,
    /// verification failed" — the <c>verify</c> operation over a PIN-path <c>pinUvAuthParam</c>
    /// returned an error.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PinAuthInvalid = 0x33;

    /// <summary>
    /// <c>CTAP2_ERR_PIN_AUTH_BLOCKED</c> (<c>0x34</c>): "PIN authentication using pinUvAuthToken
    /// blocked. Requires power cycle to reset." — three consecutive PIN mismatches have latched the
    /// power-cycle-recoverable lockout.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PinAuthBlocked = 0x34;

    /// <summary>
    /// <c>CTAP2_ERR_PIN_NOT_SET</c> (<c>0x35</c>): "No PIN has been set."
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PinNotSet = 0x35;

    /// <summary>
    /// <c>CTAP2_ERR_PUAT_REQUIRED</c> (<c>0x36</c>): "A pinUvAuthToken is required for the selected
    /// operation. See also the pinUvAuthToken option ID."
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PuatRequired = 0x36;

    /// <summary>
    /// <c>CTAP2_ERR_PIN_POLICY_VIOLATION</c> (<c>0x37</c>): "PIN policy violation. Minimum PIN length
    /// or PIN complexity may trigger this error."
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte PinPolicyViolation = 0x37;

    /// <summary>
    /// <c>CTAP2_ERR_UNAUTHORIZED_PERMISSION</c> (<c>0x40</c>): "The permissions parameter contains an
    /// unauthorized permission."
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte UnauthorizedPermission = 0x40;

    /// <summary>
    /// <c>CTAP2_ERR_UV_BLOCKED</c> (<c>0x3C</c>): built-in user verification is disabled. Returned when
    /// <c>uvRetries</c> reaches 0 — <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s own pre-check
    /// (before <c>performBuiltInUv</c> runs) and its post-error check both return this code; the
    /// <c>mc</c>/<c>ga</c> <c>options.uv</c> error ladder's own <c>uvRetries == 0</c> arm returns
    /// <see cref="PinBlocked"/> instead, the spec's own asymmetry (snapshot lines 3428/4013), NOT this
    /// code.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte UvBlocked = 0x3C;

    /// <summary>
    /// <c>CTAP2_ERR_INTEGRITY_FAILURE</c> (<c>0x3D</c>): "A checksum did not match." Returned by
    /// <c>authenticatorLargeBlobs</c>' <c>set</c> at commit time (pending length reaches
    /// <c>expectedLength</c>) when the pending buffer's trailing 16 bytes do not equal
    /// <c>LEFT(SHA-256(preceding bytes), 16)</c> (line 7666) — the stored serialized large-blob array is
    /// left UNCHANGED on this failure, on both the tokenless and token-gated write paths alike.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>, lines 9017-9019.
    /// </remarks>
    public const byte IntegrityFailure = 0x3D;

    /// <summary>
    /// <c>CTAP2_ERR_UV_INVALID</c> (<c>0x3F</c>): built-in user verification was unsuccessful.
    /// Returned by <c>getPinUvAuthTokenUsingUvWithPermissions</c> when <c>performBuiltInUv</c> fails
    /// for a reason other than a timeout or a now-zero <c>uvRetries</c> counter.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>.
    /// </remarks>
    public const byte UvInvalid = 0x3F;

    /// <summary>
    /// <c>CTAP2_ERR_INVALID_SUBCOMMAND</c> (<c>0x3E</c>): "The requested subcommand is either
    /// invalid or not implemented."
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
    /// CTAP 2.3, section 8.2: Status codes</see>, the <c>0x3E</c> row. Also
    /// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#commands">
    /// section 8.1: Command Codes</see>, line 8810: "If the authenticator implements a command code
    /// having subcommands, but does not implement an invoked subcommand, it MUST return
    /// CTAP2_ERR_INVALID_SUBCOMMAND." This MUST governs <c>authenticatorClientPIN</c>'s own
    /// unsupported-<c>subCommand</c> fallthrough — section 6.5.5's own command definition names no
    /// subcommand-not-supported status of its own to conflict with it — and
    /// <c>authenticatorConfig</c>'s step 2 (whose own bare-pseudocode text, line 7955, names
    /// <c>CTAP1_ERR_INVALID_PARAMETER</c> instead; the §8.1 MUST governs per the coordinator's R1
    /// ruling, and the two-anchor citation is repeated at both rejection sites).
    /// </remarks>
    public const byte InvalidSubcommand = 0x3E;


    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="Ok"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the command succeeded.</returns>
    public static bool IsOk(byte statusCode) => statusCode == Ok;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidCommand"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the command byte was unrecognized.</returns>
    public static bool IsInvalidCommand(byte statusCode) => statusCode == InvalidCommand;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidParameter"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a parameter's value was invalid.</returns>
    public static bool IsInvalidParameter(byte statusCode) => statusCode == InvalidParameter;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidLength"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a message or item length was invalid.</returns>
    public static bool IsInvalidLength(byte statusCode) => statusCode == InvalidLength;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidSeq"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a stateful command's fragment sequencing was invalid.</returns>
    public static bool IsInvalidSeq(byte statusCode) => statusCode == InvalidSeq;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="MissingParameter"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a non-optional parameter was missing.</returns>
    public static bool IsMissingParameter(byte statusCode) => statusCode == MissingParameter;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="CborUnexpectedType"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a nested or extension-map structure was invalid or wrong-typed.</returns>
    public static bool IsCborUnexpectedType(byte statusCode) => statusCode == CborUnexpectedType;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidCbor"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the request bytes did not parse as CTAP2 canonical CBOR.</returns>
    public static bool IsInvalidCbor(byte statusCode) => statusCode == InvalidCbor;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="CredentialExcluded"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a credential in the exclude list already exists.</returns>
    public static bool IsCredentialExcluded(byte statusCode) => statusCode == CredentialExcluded;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="FpDatabaseFull"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the fingerprint template store has no space for a new enrollment.</returns>
    public static bool IsFpDatabaseFull(byte statusCode) => statusCode == FpDatabaseFull;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="LargeBlobStorageFull"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the serialized large-blob array's capacity is exhausted.</returns>
    public static bool IsLargeBlobStorageFull(byte statusCode) => statusCode == LargeBlobStorageFull;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UnsupportedAlgorithm"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if no requested algorithm is supported.</returns>
    public static bool IsUnsupportedAlgorithm(byte statusCode) => statusCode == UnsupportedAlgorithm;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="OperationDenied"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the requested operation was not authorized.</returns>
    public static bool IsOperationDenied(byte statusCode) => statusCode == OperationDenied;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="KeyStoreFull"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if internal key storage is full.</returns>
    public static bool IsKeyStoreFull(byte statusCode) => statusCode == KeyStoreFull;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UnsupportedOption"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if an option key sent is unsupported.</returns>
    public static bool IsUnsupportedOption(byte statusCode) => statusCode == UnsupportedOption;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidOption"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if an option's value is invalid for the operation.</returns>
    public static bool IsInvalidOption(byte statusCode) => statusCode == InvalidOption;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="NoCredentials"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if no valid credential was provided or located.</returns>
    public static bool IsNoCredentials(byte statusCode) => statusCode == NoCredentials;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UserActionTimeout"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a user action timeout occurred.</returns>
    public static bool IsUserActionTimeout(byte statusCode) => statusCode == UserActionTimeout;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="NotAllowed"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a continuation command was not allowed.</returns>
    public static bool IsNotAllowed(byte statusCode) => statusCode == NotAllowed;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PinInvalid"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the presented PIN did not match.</returns>
    public static bool IsPinInvalid(byte statusCode) => statusCode == PinInvalid;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PinBlocked"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the pinRetries counter has reached 0.</returns>
    public static bool IsPinBlocked(byte statusCode) => statusCode == PinBlocked;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PinAuthInvalid"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a pinUvAuthParam failed to verify.</returns>
    public static bool IsPinAuthInvalid(byte statusCode) => statusCode == PinAuthInvalid;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PinAuthBlocked"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the power-cycle-recoverable PIN lockout is latched.</returns>
    public static bool IsPinAuthBlocked(byte statusCode) => statusCode == PinAuthBlocked;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PinNotSet"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if no PIN has been set.</returns>
    public static bool IsPinNotSet(byte statusCode) => statusCode == PinNotSet;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PuatRequired"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a pinUvAuthToken is required for the operation but none was presented.</returns>
    public static bool IsPuatRequired(byte statusCode) => statusCode == PuatRequired;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="PinPolicyViolation"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a new PIN violated the minimum-length or complexity policy.</returns>
    public static bool IsPinPolicyViolation(byte statusCode) => statusCode == PinPolicyViolation;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UnauthorizedPermission"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the permissions parameter requested an unauthorized permission.</returns>
    public static bool IsUnauthorizedPermission(byte statusCode) => statusCode == UnauthorizedPermission;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UvBlocked"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if built-in user verification is disabled.</returns>
    public static bool IsUvBlocked(byte statusCode) => statusCode == UvBlocked;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="IntegrityFailure"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if a stored checksum did not match.</returns>
    public static bool IsIntegrityFailure(byte statusCode) => statusCode == IntegrityFailure;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="UvInvalid"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if built-in user verification was unsuccessful.</returns>
    public static bool IsUvInvalid(byte statusCode) => statusCode == UvInvalid;

    /// <summary>
    /// Gets a value indicating whether <paramref name="statusCode"/> is <see cref="InvalidSubcommand"/>.
    /// </summary>
    /// <param name="statusCode">The CTAP2 response status byte to check.</param>
    /// <returns><see langword="true"/> if the requested subCommand is invalid or not implemented.</returns>
    public static bool IsInvalidSubcommand(byte statusCode) => statusCode == InvalidSubcommand;
}
