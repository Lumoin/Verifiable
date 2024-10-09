using System.Buffers.Binary;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm
{
    [TestClass]
    public sealed class TpmCommandParserTests
    {
        [TestMethod]
        public void ParsingIsFipsCommandSucceeds()
        {
            /*
            0x80, 0x01, //Tag: TPM_ST_NO_SESSIONS (2 bytes).
            0x00, 0x00, 0x00, 0x16, //Command size: 22 (4 bytes).
            0x00, 0x00, 0x01, 0x7A, //Command code: TPM_CC_GetCapability (4 bytes).
            0x00, 0x00, 0x00, 0x06, //Capability: TPM_CAP_TPM_PROPERTIES (4 bytes).
            0x00, 0x00, 0x01, 0x2D, //Property: TPM_PT_FIPS_LEVEL (4 bytes).
            0x00, 0x00, 0x00, 0x01  //Property count: 1 (4 bytes).
            */

            var isFipsCommand = new byte[] { 0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7A, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x2D, 0x00, 0x00, 0x00, 0x01 };
            var parser = new TpmCommandParser();
            var isFipsCommandBreakDown = parser.Parse(isFipsCommand);

            Assert.AreEqual(TpmConstants2Temp.TPM_ST_NO_SESSIONS, BinaryPrimitives.ReadUInt16BigEndian(isFipsCommandBreakDown[0].TpmInstruction));
            Assert.AreEqual(22u, BinaryPrimitives.ReadUInt32BigEndian(isFipsCommandBreakDown[1].TpmInstruction));
            Assert.AreEqual(Tpm2Cc.GetCapability, (Tpm2Cc)BinaryPrimitives.ReadUInt32BigEndian(isFipsCommandBreakDown[2].TpmInstruction));
            Assert.AreEqual(TPM2_CAP.TPM_PROPERTIES, (TPM2_CAP)BinaryPrimitives.ReadUInt32BigEndian(isFipsCommandBreakDown[3].TpmInstruction));
            Assert.AreEqual(Tpm2PtConstants.TPM2_PT_MODES, BinaryPrimitives.ReadUInt32BigEndian(isFipsCommandBreakDown[4].TpmInstruction));
            Assert.AreEqual(1u, BinaryPrimitives.ReadUInt32BigEndian(isFipsCommandBreakDown[5].TpmInstruction));
        }

        
        [SkipOnCiTestMethod]
        public void GetSupportedAlgorithmsCommandSucceeds()
        {
            var command = new GetCapabilityCommand();
            try
            {                
                command.GetAllSupportedAlgorithms();
            }
            finally
            {
                command.Dispose();
            }            
        }
    }
}
