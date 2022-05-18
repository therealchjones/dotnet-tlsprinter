namespace TlsObjectModel
{
	public class Handshake : RecordContent
	{
		public HandshakeType msg_type;
		HandshakeContent? msg;
		public Handshake(HandshakeContent message)
		{
			msg = message;
		}
		public Handshake(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			if (BackingBytes is not null && BackingBytes.Length > 0)
			{
				throw new InvalidOperationException("Data already added to this object. Use 'AddBytes' instead.");
			}
			AddBytes(bytes);
		}
		public override void AddBytes(byte[] bytes)
		{
			if (PendingBytes is null) PendingBytes = new byte[0];
			if (PendingBytes.Length == 0)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					msg_type = (HandshakeType)PendingBytes[0];
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length == 1)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length == 2)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length == 3)
			{
				if (bytes.Length > 0)
				{
					PendingBytes = PendingBytes.Append(bytes[0]).ToArray();
					Length = TlsUtils.BytesToUInt64(PendingBytes[1..4]);
					bytes = bytes.Remove(1);
				}
			}
			if (PendingBytes.Length >= 4)
			{
				if (Length is null) throw new InvalidOperationException();
				var remainingBytes = Length + 4 - (ulong)PendingBytes.LongLength;
				if ((ulong)bytes.LongLength <= remainingBytes)
				{
					PendingBytes = PendingBytes.Concat(bytes).ToArray();
					bytes = new byte[0];
				}
				else
				{
					PendingBytes = PendingBytes.Concat(bytes[0..(int)remainingBytes]).ToArray();
					bytes = bytes[(int)remainingBytes..];
				}
				if (bytes.Length > 0) ExtraBytes = bytes;
			}
			if ((ulong)PendingBytes.LongLength == Length + 4)
			{
				BackingBytes = PendingBytes;
				PendingBytes = new byte[0];
				switch (msg_type)
				{
					case HandshakeType.client_hello:
						msg = new ClientHello(BackingBytes[4..]);
						break;
					default:
						msg = new UnknownHandshakeContent(BackingBytes[4..]);
						break;
				}
			}
		}
		public override byte[] ToBytes()
		{
			if (Length is null || msg is null) throw new InvalidOperationException();
			byte[] msgBytes = msg.ToBytes();
			return new byte[] { (byte)msg_type }
				.Concat(GetLengthBytes())
				.Concat(msgBytes)
				.ToArray();
		}
	}
}