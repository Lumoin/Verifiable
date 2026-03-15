using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Software-only tests for the SECDSA cryptographic algorithms.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the mathematical invariants of the SECDSA protocol using
/// in-memory P-256 arithmetic. No TPM or HSM is required. Every operation that
/// would call hardware in production is performed by the software-only EcMath and
/// SecdsaAlgorithms implementations, which serve as the reference implementation
/// and the correctness baseline for the hardware paths.
/// </para>
/// <para>
/// For the hardware-backed equivalents of these tests -- where a physical TPM
/// performs the NCH signing step (TPM2_Sign) and the ECDH blinding step
/// (TPM2_ECDH_ZGen) -- see SecdsaAlgorithmsHardwareTests.
/// </para>
/// <para>
/// The system architecture tested here maps to the following components from
/// the SECDSA HSM-based EUDI Wallet specification. Key terms:
/// </para>
/// <code>
///  SCI  = Secure Cryptographic Interface: the authenticated channel between
///         the Wallet APP and the WSCA.
///  WSCA = Wallet Secure Cryptographic Application: the wallet provider's
///         server-side trusted process that authenticates signing instructions
///         and manages access to the WSCD. A software container; no bespoke
///         HSM firmware is required.
///  WSCD = Wallet Secure Cryptographic Device: the hardware that holds user
///         keys (blinding key aU). A PKCS#11 HSM or a TPM with wrapped keys.
///  NCH  = Native Cryptographic Hardware: the on-device tamper-resistant key
///         store holding the user's signing key u. TPM on Windows/Linux,
///         Secure Enclave on iOS, StrongBox on Android.
///  PID  = Person Identification Data: the foundational identity credential
///         issued to the user by a national authority (e.g. the Finnish state).
///         Stored as a Verifiable Credential on the user's phone.
///  OID4VP = OpenID for Verifiable Presentations: the protocol by which a
///           relying party requests credentials from a wallet.
///  DCQL = Digital Credentials Query Language: the query language used inside
///         an OID4VP request to specify which credential attributes are needed.
///  KYC  = Know Your Customer: the regulatory obligation requiring financial
///         institutions to verify the identity of their customers.
///
///  +---------------------------+        +--------------------------------+
///  |       Wallet APP          |        |      Wallet Provider           |
///  |                           |        |                                |
///  |  [PID credential]         |  SCI   |  +----------+  +------------+ |
///  |  [other credentials]      |&lt;------&gt;|  |  WSCA    |  |    WSCD    | |
///  |  [Internal Certificate]   |        |  | (server  |  | (hardware) | |
///  |  [Transaction Log]        |        |  | process) |  |            | |
///  |                           |        |  | eIDAS    |  | User keys  | |
///  |  Possession factor:       |        |  | High     |  | [UserDB]   | |
///  |   NCH holds u             |        |  | Auth     |  |            | |
///  |   TPM / Secure Enclave /  |        |  | endpoint |  |            | |
///  |   HBK / StrongBox         |        |  +----------+  +------------+ |
///  |                           |        |                                |
///  |  Second factor            |        |  [Transaction Log]             |
///  |  (knowledge OR inherence):|        +--------------------------------+
///  |   PIN / passphrase        |
///  |   OR biometric            |
///  +---------------------------+
///
///  Who can operate the Wallet Provider:
///
///  The WSCA is a software process -- a container or server application -- with no
///  bespoke HSM firmware required. This means the wallet provider can be:
///
///    A government body: the Finnish state, for example, may operate a public
///    wallet where it acts as both the PID issuer and the wallet provider. In that
///    case the same organisation issues Alice's PID credential and manages her
///    SECDSA keys. This is the model behind national eID wallets.
///
///    A private company: a commercial organisation (a telecom, a bank, a technology
///    provider) may operate the wallet provider infrastructure and offer wallets to
///    users, where the PID is issued by the state but the WSCA is run by the private
///    company. This is the model behind many app-based EUDI Wallet implementations.
///
///  In both cases, the Verifiable library provides the WSCA-side implementation:
///  the SECDSA cryptographic types, the NCH and WSCD delegate abstractions, the
///  InstructionTranscript, and the BlindedSecdsaInstruction. A wallet provider
///  building on this library wires up their own hardware delegates and transport
///  layer; the cryptographic protocol is implemented here.
///
///  Full party picture for the test scenario:
///
///  +------------------+   issues PID    +------------------+
///  | Finnish state    | --------------> | Alice's wallet   |
///  | (PID issuer)     |  (one-time,     | (Wallet APP +    |
///  | Signs credential |   at issuance)  |  NCH on phone)   |
///  +------------------+                 +--------+---------+
///                                                |  SCI (signing instruction)
///                                       +--------+---------+
///                                       | Wallet Provider  |
///                                       | (WSCA + WSCD)    |
///                                       | May be state or  |
///                                       | private company. |
///                                       | Uses Verifiable  |
///                                       | library.         |
///                                       +--------+---------+
///                                                |  InstructionTranscript
///                                                v
///                                       +------------------+    OID4VP VP
///  +------------------+  OID4VP request | Alice's wallet   | ------------->  +----------+
///  | EudiBank         | --------------> | assembles VP:    |                 | EudiBank |
///  | (relying party)  |  (DCQL query    |  PID credential  |                 | verifies |
///  | KYC for account  |   for PID)      |  + holder sig    |                 | issuer + |
///  | opening          |                 |                  |                 | holder   |
///  +------------------+                 +------------------+                 +----------+
///
///  Authentication factor requirements:
///
///  The EUDI Architecture Reference Framework defines strong user authentication as:
///  "An authentication based on the use of at least two authentication factors from
///  different categories of either knowledge, something only the user knows,
///  possession, something only the user possesses or inherence, something the user
///  is, that are independent, in that the breach of one does not compromise the
///  reliability of the others, and is designed in such a way as to protect the
///  confidentiality of the authentication data."
///  (EUDI ARF, <see href="https://eudi.dev/2.8.0/annexes/annex-1/annex-1-definitions/">Annex 1</see>,
///  citing Commission Implementing Regulation (EU) 2015/1502)
///
///  The EUDI Wallet operates at eIDAS assurance level High. The three factor
///  categories and their SECDSA realisations:
///
///  +--------------------+---------------------------+---------------------------+
///  | Factor category    | What it means             | SECDSA realisation        |
///  +--------------------+---------------------------+---------------------------+
///  | Possession         | Something you HAVE.       | NCH-bound private key u.  |
///  | (required)         | Something only the user   | Never leaves the NCH.     |
///  |                    | possesses. A hardware key | Proven via key attestation|
///  |                    | that cannot be copied.    | (EK/AK certificate chain).|
///  |                    |                           | TPM, Secure Enclave, HBK, |
///  |                    |                           | StrongBox all qualify.    |
///  +--------------------+---------------------------+---------------------------+
///  | Knowledge          | Something you KNOW.       | PIN-key scalar P derived  |
///  | (one option for    | Something only the user   | from user's knowledge     |
///  | the second factor) | knows. A memorised secret.| factor + NCH-bound binder |
///  |                    | A 4-6 digit numeric PIN   | key KP (Algorithms 24/25/ |
///  |                    | is the typical choice.    | 27 in Annex B). The binder|
///  |                    | Independence from the     | forces one NCH call per   |
///  |                    | possession factor is met  | attempt, enforcing rate-  |
///  |                    | because the PIN alone     | limiting and lockout.     |
///  |                    | cannot produce P without  | Covered in spec Sec 3.1.  |
///  |                    | the NCH hardware.         |                           |
///  +--------------------+---------------------------+---------------------------+
///  | Inherence          | Something you ARE.        | Static P stored under     |
///  | (alternative to    | Something the user is.    | biometric access control  |
///  | knowledge for the  | A biometric characteristic| on the device (Face ID,   |
///  | second factor)     | unique to the person:     | Touch ID, Android         |
///  |                    | fingerprint, face, iris.  | BiometricPrompt). The     |
///  |                    | The biometric unlocks     | biometric unlocks P,      |
///  |                    | access to P; it does not  | SECDSA math is identical  |
///  |                    | derive P from it.         | to the knowledge path.    |
///  |                    | Independence from the     | Covered in spec Sec 3.2.  |
///  |                    | possession factor is met  | Spec notes eIDAS High is  |
///  |                    | because the biometric     | harder to certify with    |
///  |                    | alone cannot produce P.   | biometrics due to false-  |
///  |                    |                           | acceptance rates.         |
///  +--------------------+---------------------------+---------------------------+
///
///  Both the Wallet APP and the Wallet Provider maintain a Transaction Log.
///  The wallet writes: issuance transcript (Protocol 4), every instruction
///  transcript (Algorithm 37 output). The WSCA writes: every signed transcript
///  it produces. These logs are the basis for dispute resolution.
///
///  Cryptographic log architecture:
///
///  InstructionTranscript has the shape of a signed log entry in
///  Verifiable.Core.EventLogs: a signed opaque payload, a signature, and a
///  sequence number. The EUDI Wallet-specific content is entirely inside the
///  opaque InnerTranscript bytes.
///
///  The natural extension is to make the chain explicit by adding a hash of the
///  previous transcript's canonical bytes to each entry. Replay then becomes a
///  fold: iterate entries, verify chain link, verify signature, accumulate state.
///  This is the same pattern already used in append-only cryptographic audit logs
///  in this codebase -- the transcript chain is an instance of that pattern
///  specialized for SECDSA wallet operations.
///
///  The chain integrity verification backend is a delegate that can be swapped
///  without changing the replay logic, supporting three approaches:
///
///    Hash-chain: each entry stores H(previous entry canonical bytes). Replay
///    verifies linearly. Same pattern as DID event logs.
///
///    Merkle tree: a batch of entries is committed to a single Merkle root.
///    Inclusion proofs allow verification of a single entry without replaying
///    the full chain. Same pattern as RFC 9162 Certificate Transparency.
///
///    TPM PCR quote: the chain head hash is extended into a TPM PCR and the
///    TPM produces a signed quote (TPM_Quote) over it. The quote is signed by
///    the TPM Attestation Key certified by the EK certificate chain. This proves
///    the chain was computed on a specific TPM at a specific time -- not
///    forgeable in software. Same pattern as TCG firmware event logs.
///
///  The three approaches share one fold structure; only the integrity proof
///  delegate differs. All three are stronger than a vendor-specific HSM audit
///  log because the proof is bound to the operations themselves, not produced
///  by a separate audit signing key of unverifiable provenance.
/// </code>
/// </remarks>
[TestClass]
internal sealed class SecdsaAlgorithmsSoftwareTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the full SECDSA protocol flow from wallet activation through signing,
    /// Wallet Secure Cryptographic Application (WSCA) verification, and transcript
    /// production using in-memory P-256 arithmetic.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Background -- what PID means and where credentials live:
    /// </para>
    /// <para>
    /// In the EUDI Wallet, "PID" stands for Person Identification Data: the foundational
    /// identity credential issued to Alice by a national authority (e.g. the Finnish
    /// Digital and Population Data Services Agency). It contains her legal name, date of
    /// birth, nationality, and a unique identifier -- essentially the digital equivalent
    /// of a national identity card. The PID is issued once, signed by the issuing state's
    /// key, and stored as a Verifiable Credential on Alice's phone.
    /// </para>
    /// <para>
    /// Other credentials (driving licence, diploma, professional qualification) follow the
    /// same pattern: issued by an authorised body, signed, stored locally on the phone.
    /// Alice's wallet holds a collection of these issuer-signed credentials.
    /// </para>
    /// <para>
    /// When Alice presents a credential to a relying party, she produces a Verifiable
    /// Presentation: the issuer-signed credential (stored on her phone) plus a proof of
    /// possession -- a signature proving she is the legitimate holder of that credential.
    /// The SECDSA protocol is involved only in producing that holder binding signature.
    /// The credential itself is presented directly by the wallet; the Wallet Secure
    /// Cryptographic Application (WSCA) is not involved in the credential content, only
    /// in authenticating the signing instruction.
    /// </para>
    /// <para>
    /// How the relying party knows the presenter is the genuine holder:
    /// </para>
    /// <para>
    /// At PID issuance, Alice's wallet generated the Native Cryptographic Hardware (NCH)
    /// key pair (u, U = u*G) and provided U to the Finnish state's PID issuer along with
    /// a key attestation proving u is hardware-bound and non-exportable. The PID issuer
    /// verified the attestation and signed the credential with U embedded as the holder
    /// public key: { name, date_of_birth, nationality, ..., holderPublicKey: U }. This
    /// binding is part of the signed credential.
    /// </para>
    /// <para>
    /// At presentation, EudiBank verifies two things independently:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>The Finnish state's issuer signature over the PID credential,
    ///   using the state's public key from the EUDI Wallet Trusted List. This proves the
    ///   credential and the holder public key U it contains are genuine and state-issued.
    ///   </description></item>
    ///   <item><description>Alice's holder binding signature against U. This proves the
    ///   presenter controls the private key u corresponding to U -- the same key the state
    ///   attested is NCH-bound and non-exportable. Together these two checks prove Alice is
    ///   the genuine holder of a state-issued credential bound to hardware she controls.
    ///   </description></item>
    /// </list>
    /// <para>
    /// Scenario: Alice wants to open a bank account at EudiBank remotely. EudiBank sends
    /// an OpenID for Verifiable Presentations (OID4VP) authorization request containing a
    /// Digital Credentials Query Language (DCQL) query asking for her name, date of birth,
    /// and nationality from her PID. Under eIDAS, EudiBank is entitled to request this for
    /// Know Your Customer (KYC) purposes. Alice's wallet must respond with a Verifiable
    /// Presentation: her PID credential (already on her phone, issued by the state, with U
    /// embedded as the holder public key) plus a holder binding signature signed with u and
    /// verifiable against U. Producing that signature goes through the SECDSA protocol.
    /// </para>
    /// <code>
    ///  Finnish state (PID issuer)        Alice's Wallet APP        EudiBank
    ///  --------------------------        ------------------        --------
    ///  Issues PID credential             Stores PID on phone       Sends OID4VP
    ///  Binds U as holder public key      NCH generates (u, U)      request (DCQL
    ///  Signs with state issuer key       PIN-binder key KP         query for PID)
    ///  (one-time, at PID issuance)       InternalCertificate C     Receives VP
    ///                                    Transaction Log           Verifies locally:
    ///                                                                - issuer sig
    ///                                                                - holder sig
    ///
    ///  Wallet Provider (separate from Finnish state and EudiBank)
    ///  -----------------------------------------------------------
    ///  WSCA (Wallet Secure Cryptographic Application, server process)
    ///  WSCD (Wallet Secure Cryptographic Device, hardware)
    ///  Receives one Secure Cryptographic Interface (SCI) call per signing
    ///  Does not know which relying party Alice is talking to
    ///  Returns holder binding signature + InstructionTranscript
    ///  Transaction Log
    ///
    ///  Note: EudiBank here plays two roles for narrative simplicity -- it is both
    ///  the relying party requesting the PID and the wallet provider managing Alice's
    ///  SECDSA keys. In practice these are separate organisations.
    ///
    ///  -- WHAT HAPPENS AT SETUP (two separate steps) ----------------------------
    ///
    ///  Step 1 -- PID issuance (Finnish state issues credential to Alice's wallet):
    ///    Alice's wallet generates (u, U = u*G) in the NCH and sends U to the Finnish
    ///    state's PID issuer together with a key attestation proving u is hardware-bound
    ///    and non-exportable. The state verifies the attestation and issues a signed
    ///    credential: { name, date_of_birth, nationality, holderPublicKey: U, ... }.
    ///    Alice's wallet stores this credential locally. This step involves the Finnish
    ///    state and Alice's wallet only -- the wallet provider is not involved.
    ///
    ///  Step 2 -- WSCA activation (Protocol 4, wallet provider establishes blinding):
    ///    Alice's wallet registers U with the wallet provider's WSCA. The WSCA issues
    ///    an InternalCertificate C = { AliceId, U, G' = aU*G, Y' = aU*Y } that enables
    ///    the SECDSA holder binding protocol. Alice also writes the activation transcript
    ///    to her Transaction Log. The WSCA writes it to its Transaction Log.
    ///    Y = P*U, Alice's raw SECDSA signing key, exists nowhere on disk after setup.
    ///
    ///  -- WHAT A PRESENTATION FLOW ACHIEVES --------------------------------------
    ///
    ///  EudiBank sends Alice an OID4VP request with a DCQL query for PID attributes.
    ///  Alice's wallet must return a Verifiable Presentation combining:
    ///    (a) The PID credential already stored on her phone (issuer-signed by state).
    ///    (b) A holder binding signature proving Alice controls the credential key.
    ///
    ///  To produce (b), Alice's wallet sends a SECDSA instruction to the WSCA over SCI:
    ///    1. Alice enters her knowledge factor (PIN -- "something you know").
    ///    2. Wallet derives P from PIN + NCH-bound key KP. One NCH call.
    ///    3. Builds instruction I = { "present-pid-attributes", SN=1 }.
    ///    4. Computes e' = P^-1 * H(I) mod q. NCH signs e' with u -> (r, s0).
    ///       This is the only NCH call. NCH never sees P.
    ///    5. Computes s = P * s0 mod q. Deletes P.
    ///    6. Packages BlindedSecdsaInstruction and sends to WSCA over SCI.
    ///
    ///  The WSCA:
    ///    7. Verifies NCH signature on Challenge using U from C (no WSCD needed).
    ///    8. WSCD: K = ECDH(aU, R). One hardware call.
    ///    9. Decrypts with K. Wrong PIN -> wrong K -> AES-GCM fails -> blocked.
    ///   10. Verifies ZKP and R' = e*G'' + r*Y''.
    ///   11. Executes instruction: returns the holder binding signature result.
    ///   12. Signs InstructionTranscript TI. Writes T to Transaction Log.
    ///   13. Returns T to Alice's wallet. Alice writes T to her Transaction Log.
    ///
    ///  Alice's wallet assembles the Verifiable Presentation from (a) and (b) and
    ///  returns it to EudiBank over the OID4VP channel.
    ///
    ///  -- WHAT THE TRANSCRIPT PROVES ---------------------------------------------
    ///
    ///  Anyone holding T = { TI, Sig } and C can verify without WSCD access:
    ///    - Sig is valid over TI using the public transcript key S.
    ///    - ZKP confirms G'' and Y'' are honestly derived.
    ///    - R' = e*G'' + r*Y'' holds.
    ///    - Protocol 2 or Algorithm 23 confirms R' = aU*R.
    ///  This provides sole control and non-repudiation at eIDAS High assurance level.
    /// </code>
    /// </remarks>
    [TestMethod]
    public void FullSecdsaProtocolFlowSoftwareCryptographicInvariantsHold()
    {
        //-- ACTIVATION: Alice's wallet generates the NCH key pair -----------------
        //
        //Alice's phone asks its Native Cryptographic Hardware (NCH) -- e.g. a Windows
        //TPM, iOS Secure Enclave, or Android StrongBox -- to generate a P-256 key pair.
        //The NCH returns only U = u*G. The private key u is non-exportable and stays
        //inside the NCH forever. In this software test u is an in-memory scalar; on
        //real hardware it is a key handle and the signing call would be TPM2_Sign.

        BigInteger u = EcMath.RandomScalar();
        EcPoint U = EcMath.BasePointMultiply(u);

        Assert.IsTrue(EcMath.IsValidPoint(U),
            "Alice's NCH public key U = u*G must be a valid P-256 point.");

        //-- ACTIVATION: Alice sets her PIN and the wallet derives P ---------------
        //
        //Alice enters her knowledge factor -- typically a 4-to-6-digit numeric PIN
        //such as "123456", though the PIN-binder construction works for any byte
        //sequence the user memorises. The wallet derives the PIN-key scalar P from
        //the PIN value and the NCH-bound PIN-binder key KP (one NCH call) using one
        //of the constructions in Annex B (HMAC-based Algorithm 24, RSA-based
        //Algorithm 25, or ECDH-based Algorithm 27). P is ephemeral -- computed on
        //demand, used once, then discarded. It never persists on disk.
        //Here a random scalar stands in for the PIN-binder derivation.

        BigInteger P = EcMath.RandomScalar();

        //-- ACTIVATION: wallet computes Y = P*U and immediately blinds it ---------
        //
        //Y = P*U = P*u*G is Alice's raw SECDSA signing key. It is computed in
        //memory for exactly long enough to derive Y' (the blinded form) and is
        //then deleted. Y must never be stored: an attacker who has Y and NCH access
        //can enumerate PINs until P*u*G = Y.
        //
        //The wallet blinds Y with a fresh random t: Ybl = t*Y. Only Ybl is sent
        //to EudiBank. EudiBank's HSM computes Y'bl = aU*Ybl. The wallet removes
        //the blinding: Y' = t^-1 * Y'bl = aU*Y. EudiBank never sees Y.

        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, P);
        EcPoint Y = keyPair.PublicKey;

        Assert.IsTrue(EcMath.IsValidPoint(Y),
            "Alice's SECDSA public key Y = P*u*G must be a valid P-256 point.");

        BigInteger t = EcMath.RandomScalar();
        EcPoint Ybl = EcMath.Multiply(Y, t);

        //-- ACTIVATION: EudiBank's HSM computes the blinding ----------------------
        //
        //EudiBank generates a fresh user blinding scalar aU inside its PKCS#11 HSM.
        //aU is non-exportable. The HSM computes Y'bl = aU*Ybl via CKM_ECDH1_DERIVE.
        //G' = aU*G is the blinding public key stored in Alice's InternalCertificate.
        //
        //A PKCS#11 HSM is used here -- not a TPM -- because the operation requires
        //CKM_ECDH1_DERIVE on a server under EudiBank's control. A server TPM with
        //TPM2_ECDH_ZGen is technically feasible but not the typical deployment.

        BigInteger aU = EcMath.RandomScalar();
        EcPoint Gprime = EcMath.BasePointMultiply(aU);
        EcPoint Ybl_prime = EcMath.Multiply(Ybl, aU);

        BigInteger tInv = EcMath.ModInverse(t);
        EcPoint Yprime = EcMath.Multiply(Ybl_prime, tInv);

        //Invariant: the blinding round-trip Y' = t^-1 * aU * t * Y must equal aU*Y.
        //If this fails, the modular inverse or the point multiplication is incorrect.
        Assert.AreEqual(EcMath.Multiply(Y, aU), Yprime,
            "Blind SECDSA public key Y' = aU*Y must equal t^-1 * aU * t * Y after the blinding round-trip.");

        //-- SIGNING: Alice responds to EudiBank's OID4VP request ------------------
        //
        //Four parties are involved; it is essential to know which talks to which:
        //
        //  Finnish state (Person Identification Data issuer) -- no network activity
        //    during this presentation. Issued Alice's PID at wallet activation, signed
        //    with its issuer key. EudiBank verifies that signature using the state's
        //    public key from the EUDIW Trusted List, resolved at setup time.
        //
        //  Wallet provider (operates Wallet Secure Cryptographic Application (WSCA)
        //    and Wallet Secure Cryptographic Device (WSCD)) -- receives one Secure
        //    Cryptographic Interface (SCI) call from Alice's wallet. Separate from
        //    both the Finnish state and EudiBank. Does not know which relying party
        //    Alice is talking to.
        //
        //  Alice's wallet app -- makes two outbound connections:
        //    1. To the wallet provider's WSCA over SCI: to get the holder binding
        //       signature (b below).
        //    2. To EudiBank over OpenID for Verifiable Presentations (OID4VP): to
        //       return the completed Verifiable Presentation (VP).
        //
        //  EudiBank (relying party) -- sends one OID4VP request, receives one VP.
        //    Verifies locally: the Finnish state's issuer signature and Alice's holder
        //    binding signature. No call to wallet provider or Finnish state.
        //
        //Alice's VP combines:
        //  (a) PID credential from local storage -- issuer-signed by the Finnish state.
        //      Read directly from Alice's phone. WSCA not involved.
        //  (b) Holder binding signature -- produced via the SECDSA protocol below.
        //
        //SECDSA Algorithm 2:
        //  a. e = H(I) as an integer mod q.
        //  b. e' = P^-1 * e mod q  -- the hash is adjusted using Alice's PIN-key.
        //  c. NCH (Native Cryptographic Hardware) raw-signs e': (r, s0).
        //     Hardware boundary (TPM2_Sign in production). NCH never sees P.
        //  d. s = P * s0 mod q  -- signature is re-scaled using the PIN-key.
        //The result (r, s) is valid ECDSA under Y = P*u*G even though the NCH
        //saw only e' and never saw P. This is Proposition 3.1 of the SECDSA spec.

        byte[] instructionHash = SHA256.HashData("present-pid-attributes SN=1"u8);
        EcdsaSignature sig = SecdsaAlgorithms.Sign(instructionHash, u, P);

        Assert.IsTrue(SecdsaAlgorithms.Verify(instructionHash, sig, Y),
            "Alice's SECDSA signature must verify under her public key Y (Algorithm 14).");

        //-- SIGNING: convert to full format for the WSCA --------------------------
        //
        //Full format (R, s) is needed because the WSCA must compute the ECDH
        //verification equation R' = e*G'' + r*Y'' using the full nonce point R = k*G,
        //not just its x-coordinate r.

        FullEcdsaSignature fullSig = SecdsaAlgorithms.ToFullFormat(sig, instructionHash, Y);

        Assert.IsTrue(SecdsaAlgorithms.VerifyFull(instructionHash, fullSig, Y),
            "Full-format SECDSA signature must verify under Y (Algorithm 15).");
        Assert.IsTrue(EcMath.IsValidPoint(fullSig.RPoint),
            "Nonce point R = k*G must be a valid P-256 point.");

        //-- SIGNING: Alice computes G'' and Y'' using InternalCertificate ---------
        //
        //From C = { AliceId, U, G', Y' }, the wallet computes:
        //  G'' = s^-1 * G'  (scaled blinding public key)
        //  Y'' = s^-1 * Y'  (scaled blind SECDSA public key)
        //These values are included in the AES-GCM ciphertext sent to the WSCA.

        BigInteger sInv = EcMath.ModInverse(fullSig.S);
        EcPoint Gdouble = EcMath.Multiply(Gprime, sInv);
        EcPoint Ydouble = EcMath.Multiply(Yprime, sInv);

        Assert.IsTrue(EcMath.IsValidPoint(Gdouble),
            "Scaled blinding key G'' = s^-1 * G' must be a valid P-256 point.");
        Assert.IsTrue(EcMath.IsValidPoint(Ydouble),
            "Scaled blind public key Y'' = s^-1 * Y' must be a valid P-256 point.");

        //-- SIGNING: Schnorr ZKP proves G'' and Y'' are honestly derived ----------
        //
        //Alice's wallet generates a ZKP proving that G'' and Y'' share the same
        //discrete logarithm s^-1 relative to G' and Y' (Algorithm 19). This
        //prevents Alice from submitting a tampered G''/Y'' pair that would bypass
        //the WSCA's verification step. The ZKP is inside the ciphertext.

        SchnorrZkProof zkp = SchnorrZkp.Generate(
            generators: [Gprime, Yprime],
            publicKeys: [Gdouble, Ydouble],
            witness: sInv,
            challengeBinding: ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(SchnorrZkp.Verify(
            proof: zkp,
            generators: [Gprime, Yprime],
            publicKeys: [Gdouble, Ydouble],
            challengeBinding: ReadOnlySpan<byte>.Empty),
            "Schnorr ZKP must confirm that G'' = s^-1 * G' and Y'' = s^-1 * Y' share the same discrete log.");

        //-- WSCA VERIFICATION: ECDH equation proves Alice used the correct PIN ----
        //
        //EudiBank's WSCA computes R' = e*G'' + r*Y'' from the decrypted payload.
        //EudiBank's HSM independently computes aU*R from R (the nonce point) and
        //the HSM-bound blinding key aU via one PKCS#11 CKM_ECDH1_DERIVE call.
        //
        //If Alice entered the correct PIN, R' equals aU*R. The mathematical identity
        //establishing this (Proposition 3.3):
        //  e*G'' + r*Y'' = e*s^-1*G' + r*s^-1*Y'
        //                = e*s^-1*aU*G + r*s^-1*aU*Y   (by definition of G', Y')
        //                = aU*(e*s^-1*G + r*s^-1*Y)
        //                = aU*R                         (ECDSA verification equation)
        //
        //If Alice entered the wrong PIN, P is different, s is different, G''/Y'' are
        //different, and R' does not equal aU*R. Consequently the AES-GCM key K,
        //derived from aU*R, does not match the key used for encryption, and the WSCA
        //rejects the instruction without ever learning what the correct PIN is.

        BigInteger e = EcMath.HashToInteger(instructionHash);
        BigInteger rScalar = fullSig.RPoint.X % EcMath.Q;
        EcPoint Rprime = EcMath.Add(
            EcMath.Multiply(Gdouble, e),
            EcMath.Multiply(Ydouble, rScalar));

        EcPoint aUR = EcMath.Multiply(fullSig.RPoint, aU);

        Assert.AreEqual(aUR, Rprime,
            "ECDH verification equation R' = e*G'' + r*Y'' must equal aU*R (Proposition 3.3). " +
            "This is the central invariant proving Alice used the correct PIN.");

        //-- TRANSCRIPT: EudiBank signs the execution result -----------------------
        //
        //The WSCA bundles { I, R, G'', Y'', ZKP, Challenge, H1, Res } into TI and
        //signs it with its transcript key s. The signature Sig over TI is what
        //Alice stores and what any third party uses to verify the audit trail.
        //The same sequence number from Alice's instruction appears in the transcript
        //so a judge can correlate the signed instruction to the signed result.
        //
        //After this step:
        //  - The wallet provider's WSCA writes T = { TI, Sig } to its Transaction Log.
        //  - Alice's Wallet APP receives T, writes it to its Transaction Log, and
        //    uses the signed result to construct the Verifiable Presentation returned
        //    to EudiBank over the OID4VP channel.
        //  Both logs hold independently verifiable evidence of the wallet operation.
        //  EudiBank's OID4VP session with the wallet is a separate channel.

        const ulong sn = 1UL;

        using EcPointBytes noncePointBytes = EcPointBytes.Create(
            EcMath.EncodePointUncompressed(fullSig.RPoint), MemoryPool<byte>.Shared);
        using EcPointBytes verificationPointBytes = EcPointBytes.Create(
            EcMath.EncodePointUncompressed(Rprime), MemoryPool<byte>.Shared);

        using BlindedSecdsaInstruction instruction = BlindedSecdsaInstruction.Create(
            sequenceNumber: sn,
            challengeBytes: new byte[32],
            noncePoint: noncePointBytes,
            verificationPoint: verificationPointBytes,
            ciphertextBytes: new byte[64],
            authTagBytes: new byte[16],
            pool: MemoryPool<byte>.Shared);

        using InstructionTranscript transcript = InstructionTranscript.Create(
            sequenceNumber: sn,
            innerTranscriptBytes: new byte[128],
            wscaSignatureBytes: new byte[64],
            executionResultBytes: new byte[32],
            pool: MemoryPool<byte>.Shared);

        Assert.AreEqual(instruction.SequenceNumber, transcript.SequenceNumber,
            "Transcript sequence number must match the originating instruction so a judge can correlate them.");

        Assert.AreEqual(fullSig.RPoint, EcMath.DecodePointUncompressed(instruction.NoncePoint.Value.Span),
            "Nonce point R must survive the encode/decode round-trip through EcPointBytes.");
        Assert.AreEqual(Rprime, EcMath.DecodePointUncompressed(instruction.VerificationPoint.Value.Span),
            "ECDH verification point R' must survive the encode/decode round-trip through EcPointBytes.");
    }


    /// <summary>
    /// Verifies the SECDSA split key architecture (Section 4, Algorithm 11, Option I),
    /// where EudiBank's HSM manages one base attestation key per user and all individual
    /// attestation signing keys are derived outside the HSM using a wallet key-share.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Scenario: Alice has a driving licence attestation and a national ID attestation.
    /// In the standard SECDSA design (Section 3), EudiBank's HSM would hold two separate
    /// signing keys -- one per attestation. With millions of users and multiple attestations
    /// each, that becomes a key management problem.
    /// </para>
    /// <para>
    /// The split key architecture reduces the HSM to one base key per user. Alice's wallet
    /// generates a fresh key-share scalar zU for each attestation and derives the attestation
    /// signing key as Y = zU * B, where B = bU*G is EudiBank's base public key for Alice.
    /// No new key needs to be generated or stored in the HSM for each attestation.
    /// </para>
    /// <para>
    /// Option I (wallet-managed key-share, the simplest variant):
    /// </para>
    /// <code>
    ///  Alice's wallet                    EudiBank's HSM
    ///  --------------                    --------------
    ///  holds key-share zU                holds base key bU (non-exportable, one per user)
    ///  derives Y = zU * B               B = bU*G is published in Alice's registration
    ///
    ///  Signing a driving-licence attestation (Algorithm 11 Option I):
    ///    1. e  = H(instruction)
    ///    2. e' = e * zU^-1 mod q         (wallet adjusts hash with key-share)
    ///    3. (r, s0) = HSM_Sign(e', bU)   (HSM boundary: one call, same as Algorithm 2)
    ///    4. s  = zU * s0 mod q           (wallet re-scales with key-share)
    ///
    ///  Result (r, s) verifies under Y = zU*bU*G.
    ///
    ///  Signing a national-ID attestation uses a different zU' and Y' = zU'*B.
    ///  Both use the same bU in the HSM -- only one HSM key per user.
    ///
    ///  Neither Alice alone (she has no bU) nor EudiBank alone (it has no zU)
    ///  can produce a valid signature for Y.
    /// </code>
    /// <para>
    /// This is algebraically identical to Algorithm 2 with zU playing the role of P
    /// (PIN-key) and bU playing the role of u (NCH key). The same verification
    /// algorithms (14 and 15) apply without modification. The PIN factor from
    /// Algorithm 2 can be layered on top by replacing zU with P*zU.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplitKeyArchitectureSignAndVerifyInvariantsHold()
    {
        //-- EudiBank's HSM: one base attestation key for Alice --------------------
        //
        //EudiBank generates bU inside its HSM once during Alice's wallet activation.
        //All of Alice's attestation keys derive from this single base key.
        //bU is non-exportable. Only B = bU*G is published in Alice's registration.
        //In this software test bU is an in-memory scalar; in production it is a
        //PKCS#11 key handle and signing uses CKM_ECDSA or equivalent.

        BigInteger bU = EcMath.RandomScalar();
        EcPoint B = EcMath.BasePointMultiply(bU);

        Assert.IsTrue(EcMath.IsValidPoint(B),
            "EudiBank's HSM base public key B = bU*G must be a valid P-256 point.");

        //-- Alice's wallet: derive a driving-licence attestation key --------------
        //
        //For her driving licence attestation, Alice's wallet generates a fresh
        //key-share scalar zU and computes the attestation signing key:
        //  Y = zU * B = zU * bU * G
        //No HSM call is needed for key generation. The same bU in EudiBank's HSM
        //is used for all of Alice's attestations.

        BigInteger zU = EcMath.RandomScalar();
        (EcPoint Y, BigInteger _) = SecdsaAlgorithms.GenerateKeyPairFromBaseKey(B, zU);

        Assert.IsTrue(EcMath.IsValidPoint(Y),
            "Driving licence attestation key Y = zU*B must be a valid P-256 point.");

        //Invariant: Y = zU*B must equal zU*bU*G computed directly.
        Assert.AreEqual(EcMath.BasePointMultiply(zU * bU % EcMath.Q), Y,
            "Y = zU*B must equal zU*bU*G: key derivation must be consistent with the base key.");

        //-- Alice and EudiBank jointly sign a driving-licence credential ----------
        //
        //Alice's wallet adjusts the hash with her key-share and EudiBank's HSM
        //signs the adjusted hash with bU (one HSM call). Alice's wallet re-scales
        //the signature with her key-share. The result verifies under Y = zU*bU*G.

        byte[] instructionHash = SHA256.HashData("present-driving-licence SN=1"u8);
        EcdsaSignature sig = SecdsaAlgorithms.SignWithKeyShare(instructionHash, bU, zU);

        Assert.IsTrue(SecdsaAlgorithms.Verify(instructionHash, sig, Y),
            "Split key signature on driving-licence instruction must verify under Y = zU*bU*G (Algorithm 14).");

        FullEcdsaSignature fullSig = SecdsaAlgorithms.ToFullFormat(sig, instructionHash, Y);
        Assert.IsTrue(SecdsaAlgorithms.VerifyFull(instructionHash, fullSig, Y),
            "Split key signature must verify in full format under Y (Algorithm 15).");

        //-- Alice's national-ID attestation uses a different key-share ------------
        //
        //For her national ID attestation, Alice's wallet generates a different
        //key-share zU2. The attestation key Y2 = zU2*B is independent of Y.
        //EudiBank's HSM still uses the same bU -- only Alice's key-share changes.

        BigInteger zU2 = EcMath.RandomScalar();
        (EcPoint Y2, BigInteger _) = SecdsaAlgorithms.GenerateKeyPairFromBaseKey(B, zU2);

        byte[] nationalIdHash = SHA256.HashData("present-national-id SN=1"u8);
        EcdsaSignature sig2 = SecdsaAlgorithms.SignWithKeyShare(nationalIdHash, bU, zU2);

        Assert.IsTrue(SecdsaAlgorithms.Verify(nationalIdHash, sig2, Y2),
            "Split key signature on national-ID instruction must verify under Y2 = zU2*bU*G.");

        //Cross-check: driving-licence signature does not verify under national-ID key.
        Assert.IsFalse(SecdsaAlgorithms.Verify(instructionHash, sig, Y2),
            "Driving-licence signature must not verify under the national-ID attestation key.");

        //-- Wrong key-share produces an unverifiable signature --------------------
        //
        //If Alice's wallet uses a corrupted or wrong key-share zU3 != zU, the
        //signature is computed under Y3 = zU3*bU*G != Y and must not verify under Y.
        //This confirms that the key-share is cryptographically bound to the result.

        BigInteger zU3 = EcMath.RandomScalar();
        EcdsaSignature sigWrongShare = SecdsaAlgorithms.SignWithKeyShare(instructionHash, bU, zU3);

        Assert.IsFalse(SecdsaAlgorithms.Verify(instructionHash, sigWrongShare, Y),
            "Signature produced with a wrong key-share must not verify under Y.");
    }
}