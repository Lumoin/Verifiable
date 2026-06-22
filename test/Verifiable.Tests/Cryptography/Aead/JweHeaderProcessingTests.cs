using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests <see cref="JweHeaderProcessing.Validate(ReadOnlySpan{byte}, string)"/> and its
/// understood-extensions overload over decoded protected-header JSON: the rejected-by-design
/// algorithm guards (<c>RSA1_5</c> per RFC 8725 §3.2, <c>zip</c> per RFC 8725 §3.6), the
/// duplicate-Header-Parameter rejection (RFC 7516 §4 / §5.2 step 4), and the full <c>crit</c>
/// processing rules of RFC 7515 §4.1.11 / RFC 7516 §5.2 step 5.
/// </summary>
/// <remarks>
/// The unit under test reads a UTF-8 JSON protected header through the library's span reader, so
/// each case feeds a small hand-written header encoded with <see cref="Encoding.UTF8"/>. Every
/// rejection path throws <see cref="FormatException"/>; the accepting paths return without
/// throwing.
/// </remarks>
[TestClass]
internal sealed class JweHeaderProcessingTests
{
    public TestContext TestContext { get; set; } = null!;


    //Returns a byte[] rather than a ReadOnlySpan<byte> so the header can be captured by the
    //Assert.Throws lambdas below; a ref struct span cannot be used inside a lambda. The
    //byte[] converts implicitly to the Validate parameter's ReadOnlySpan<byte> at the call site.
    private static byte[] HeaderBytes(string json) => Encoding.UTF8.GetBytes(json);


    [TestMethod]
    public void Validate_RejectsRsa15()
    {
        //RFC 8725 §3.2: RSAES-PKCS1-v1_5 is rejected as Bleichenbacher-vulnerable. The guard keys
        //off the already-extracted alg value, not the header body.
        byte[] header = HeaderBytes("{\"alg\":\"RSA1_5\",\"enc\":\"A256GCM\"}");

        FormatException exception = Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "RSA1_5"));

        Assert.Contains("RFC 8725 §3.2", exception.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void Validate_RejectsZipHeader()
    {
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"zip\":\"DEF\"}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW"),
            "A 'zip' compression parameter must be rejected (RFC 8725 §3.6).");
    }


    [TestMethod]
    public void Validate_RejectsDuplicateTopLevelName()
    {
        //RFC 7516 §4 / §5.2 step 4: Header Parameter names MUST be unique. A header repeating
        //"alg" is the validate-one/act-on-another divergence the gate closes.
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES\",\"enc\":\"A256GCM\",\"alg\":\"dir\"}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES"),
            "A duplicate top-level Header Parameter name must be rejected (RFC 7516 §4 / §5.2 step 4).");
    }


    [TestMethod]
    public void Validate_RejectsEmptyCritList()
    {
        //RFC 7515 §4.1.11: producers MUST NOT use the empty list "[]" as the "crit" value.
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"crit\":[]}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW"),
            "An empty 'crit' list must be rejected (RFC 7515 §4.1.11).");
    }


    [TestMethod]
    public void Validate_RejectsCritNamingRegisteredParameter()
    {
        //RFC 7515 §4.1.11: producers MUST NOT list specification-registered names in "crit".
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"crit\":[\"enc\"]}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW"),
            "A 'crit' entry naming the registered parameter 'enc' must be rejected (RFC 7515 §4.1.11).");
    }


    [TestMethod]
    public void Validate_RejectsCritNameAbsentFromHeader()
    {
        //RFC 7515 §4.1.11: names in "crit" MUST occur as Header Parameter names in the JOSE Header.
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"crit\":[\"foo\"]}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW"),
            "A 'crit' entry naming a parameter absent from the header must be rejected (RFC 7515 §4.1.11).");
    }


    [TestMethod]
    public void Validate_RejectsCritNonStringArray()
    {
        //A present "crit" whose value is not a string array is a malformed producer header rather
        //than an absent "crit" (RFC 7515 §4.1.11).
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"crit\":\"x\"}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW"),
            "A 'crit' value that is not a JSON array of strings must be rejected (RFC 7515 §4.1.11).");
    }


    [TestMethod]
    public void Validate_RejectsUndeclaredCriticalExtension()
    {
        //RFC 7516 §5.2 step 5: a critical extension the recipient does not understand makes the
        //message invalid. The no-understood-extension overload declares none.
        byte[] header =
            HeaderBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"crit\":[\"foo\"],\"foo\":1}");

        Assert.Throws<FormatException>(() =>
            JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW"),
            "An undeclared critical extension must be rejected (RFC 7516 §5.2 step 5).");
    }


    [TestMethod]
    public void Validate_AcceptsDeclaredUnderstoodCriticalExtension()
    {
        //RFC 7515 §4.1.11: a critical extension the recipient understands and processes is
        //accepted. The caller declares "foo" understood.
        byte[] header =
            Encoding.UTF8.GetBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\",\"crit\":[\"foo\"],\"foo\":1}");
        IReadOnlySet<string> understood = new HashSet<string>(StringComparer.Ordinal) { "foo" };

        JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW", understood);
    }


    [TestMethod]
    public void Validate_AbsentCritIsAccepted()
    {
        //A well-formed header without a "crit" parameter passes the crit validation untouched.
        byte[] header = Encoding.UTF8.GetBytes("{\"alg\":\"ECDH-ES+A256KW\",\"enc\":\"A256GCM\"}");

        JweHeaderProcessing.Validate(header, "ECDH-ES+A256KW");
    }
}
