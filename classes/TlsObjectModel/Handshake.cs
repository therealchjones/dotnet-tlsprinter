namespace TlsObjectModel
{
	public class Handshake : RecordContent
	{
		public HandshakeType msg_type;
		HandshakeLength length;
		HandshakeMessage? msg;
		public Handshake(HandshakeMessage message)
		{
			msg = message;
		}
		public Handshake(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override void AddBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override byte[] ToBytes()
		{
			throw new NotImplementedException();
		}
	}
	internal struct HandshakeLength
	{
		byte[] bytes = new byte[3] { 0, 0, 0 }; // stored in bigendian order
		public UInt32 Length
		{
			get
			{
				if (bytes is null) return 0;
				return GetUInt24(bytes);
			}
			set
			{
				bytes = FromUInt24(value);
			}
		}
		public HandshakeLength(byte[] valueBytes)
		{
			if (valueBytes.Length != 3) throw new ArgumentException();
			bytes = valueBytes;
		}
		public HandshakeLength(UInt32 value)
		{
			Length = value;
		}
		UInt32 GetUInt24(byte[] intBytes)
		{
			if (bytes.Length != 3) throw new InvalidOperationException();
			intBytes = new byte[] { 0 }.Concat(intBytes).ToArray();
			if (BitConverter.IsLittleEndian) intBytes = intBytes.Reverse().ToArray();
			return BitConverter.ToUInt32(intBytes);
		}
		byte[] FromUInt24(UInt32 value)
		{
			byte[] intBytes = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) intBytes = intBytes.Reverse().ToArray();
			if (intBytes[0] != 0) throw new OverflowException();
			return new ArraySegment<byte>(intBytes, 1, 3).ToArray();
		}
		byte[] ToBytes()
		{
			return bytes;
		}
	}
}