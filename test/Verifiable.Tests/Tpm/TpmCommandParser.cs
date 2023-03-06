using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Tpm
{
    /// <summary>
    /// The well defined states <see cref="TpmCommandParser"/> can be in.
    /// </summary>
    public enum ParserState
    {
        None = 0,
        Tag,
        CommandSize,
        CommandCode,
        Capability,
        Property,
        PropertyCount,
        End,

        //TODO: More states here...
    }

    public readonly record struct ParsedData(byte[] TpmInstruction, string Explanation);
    
    class TpmCommandParser
    {
        public delegate ParsedData TpmParser(ref SequenceReader<byte> reader);


        public IList<ParsedData> Parse(byte[] rawCommandBuffer)
        {
            List<ParsedData> result = new();
            ReadOnlyMemory<byte> memory = new ReadOnlyMemory<byte>(rawCommandBuffer);
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(memory);
            SequenceReader<byte> reader = new SequenceReader<byte>(sequence);

            ParserState state = ParserState.Tag;

            while(!reader.End && state != ParserState.End)
            {
                //Select the appropriate parser based on the current state.
                var parser = SelectParser(state);

                //Parses the data using the selected parser.
                var parsedData = parser(ref reader);

                //Builds up the result from the parsed data.
                result.Add(parsedData);

                //Updates the state for the next sequence to be parsed according
                //to the current state and TPM 2 specifications.
                state = GetNextState(state, parsedData, result);
            }

            return result;
        }


        private static TpmParser SelectParser(ParserState state)
        {
            return state switch
            {
                ParserState.Tag => TagParser,
                ParserState.CommandSize => CommandSizeParser,
                ParserState.CommandCode => CommandCodeParser,
                ParserState.Capability => CapabilityParser,
                ParserState.Property => PropertyParser,
                ParserState.PropertyCount => PropertyCountParser,
                
                //TODO: More parsers here...
                
                _ => throw new InvalidOperationException($"Unexpected parser state: {state}")
            };
        }

        private static ParserState GetNextState(ParserState currentState, ParsedData parsedData, List<ParsedData> result)
        {
            ParserState nextState = (currentState, parsedData, result) switch
            {
                (ParserState.Tag, _, _) => ParserState.CommandSize,
                (ParserState.CommandSize, _, _) => ParserState.CommandCode,
                (ParserState.CommandCode, _, _) => ParserState.Capability,
                (ParserState.Capability, _, _) => ParserState.Property,
                (ParserState.Property, _, _) => ParserState.PropertyCount,
                (ParserState.PropertyCount, _, _) => ParserState.End,
                // Add more cases as needed
                _ => throw new InvalidOperationException($"Unexpected parser state: {currentState}")
            };

            return nextState;
        }


        public static ParsedData TagParser(ref SequenceReader<byte> reader)
        {
            if(reader.TryRead(out byte firstByte) && reader.TryRead(out byte secondByte))
            {
                ushort value = BinaryPrimitives.ReadUInt16BigEndian(new ReadOnlySpan<byte>(new[] { firstByte, secondByte }));
                return new ParsedData(new[] { firstByte, secondByte }, $"Tag: 0x{value:X4}");
            }

            throw new InvalidOperationException("Unexpected data in the command buffer.");
        }

        public static ParsedData CommandSizeParser(ref SequenceReader<byte> reader)
        {
            if(reader.TryRead(out byte firstByte) && reader.TryRead(out byte secondByte) && reader.TryRead(out byte thirdByte) && reader.TryRead(out byte fourthByte))
            {
                uint commandSize = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(new[] { firstByte, secondByte, thirdByte, fourthByte }));
                return new ParsedData(new[] { firstByte, secondByte, thirdByte, fourthByte }, $"Command size: {commandSize}");
            }

            throw new InvalidOperationException("Unexpected data in the command buffer.");
        }

        public static ParsedData CommandCodeParser(ref SequenceReader<byte> reader)
        {
            if(reader.TryRead(out byte firstByte) && reader.TryRead(out byte secondByte) && reader.TryRead(out byte thirdByte) && reader.TryRead(out byte fourthByte))
            {
                uint commandCode = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(new[] { firstByte, secondByte, thirdByte, fourthByte }));
                return new ParsedData(new[] { firstByte, secondByte, thirdByte, fourthByte }, $"Command code: 0x{commandCode:X4}");
            }

            throw new InvalidOperationException("Unexpected data in the command buffer.");
        }

        public static ParsedData CapabilityParser(ref SequenceReader<byte> reader)
        {
            if(reader.TryRead(out byte firstByte) && reader.TryRead(out byte secondByte) && reader.TryRead(out byte thirdByte) && reader.TryRead(out byte fourthByte))
            {
                uint capability = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(new[] { firstByte, secondByte, thirdByte, fourthByte }));
                return new ParsedData(new[] { firstByte, secondByte, thirdByte, fourthByte }, $"Capability: 0x{capability:X8}");
            }

            throw new InvalidOperationException("Unexpected data in the command buffer.");
        }

        public static ParsedData PropertyParser(ref SequenceReader<byte> reader)
        {
            if(reader.TryRead(out byte firstByte) && reader.TryRead(out byte secondByte) && reader.TryRead(out byte thirdByte) && reader.TryRead(out byte fourthByte))
            {
                uint property = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(new[] { firstByte, secondByte, thirdByte, fourthByte }));
                return new ParsedData(new[] { firstByte, secondByte, thirdByte, fourthByte }, $"Property: 0x{property:X8}");
            }

            throw new InvalidOperationException("Unexpected data in the command buffer.");
        }


        public static ParsedData PropertyCountParser(ref SequenceReader<byte> reader)
        {
            if(reader.TryRead(out byte firstByte) && reader.TryRead(out byte secondByte) && reader.TryRead(out byte thirdByte) && reader.TryRead(out byte fourthByte))
            {
                uint propertyCount = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(new[] { firstByte, secondByte, thirdByte, fourthByte }));
                return new ParsedData(new[] { firstByte, secondByte, thirdByte, fourthByte }, $"Property count: 0x{propertyCount:X8}");
            }

            throw new InvalidOperationException("Unexpected data in the command buffer.");
        }
    }
}
