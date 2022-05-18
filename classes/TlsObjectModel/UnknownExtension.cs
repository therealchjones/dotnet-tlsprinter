namespace TlsObjectModel
{
	public class UnknownExtension : Extension
	{
		ushort ExtensionType;
		byte[] ExtensionData = new byte[0];
		public UnknownExtension(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			if (BackingBytes is not null && BackingBytes.Length > 0) throw new InvalidOperationException();
			AddBytes(bytes);
		}
		public override void AddBytes(byte[] bytes)
		{
			ArgumentNullException.ThrowIfNull(bytes);
			if (BackingBytes is null) BackingBytes = new byte[0];
			ushort dataLength = 0;
			while (bytes.Length > 0)
			{
				switch (BackingBytes.LongLength)
				{
					case 0:
						BackingBytes = BackingBytes.Append(bytes[0]).ToArray();
						bytes = bytes.Remove(1);
						break;
					case 1:
						BackingBytes = BackingBytes.Append(bytes[0]).ToArray();
						bytes = bytes.Remove(1);
						ExtensionType = (ushort)TlsUtils.BytesToUInt64(BackingBytes[0..2]);
						break;
					case 2:
						BackingBytes = BackingBytes.Append(bytes[0]).ToArray();
						bytes = bytes.Remove(1);
						break;
					case 3:
						BackingBytes = BackingBytes.Append(bytes[0]).ToArray();
						bytes = bytes.Remove(1);
						dataLength = (ushort)TlsUtils.BytesToUInt64(BackingBytes[2..4]);
						break;
					case 4:
						if ((ushort)bytes.Length != dataLength) throw new InvalidDataException();
						BackingBytes = BackingBytes.Concat(bytes).ToArray();
						ExtensionData = bytes;
						bytes = new byte[0];
						break;
					default:
						throw new InvalidOperationException();
				}
			}
		}
		public override byte[] ToBytes()
		{
			if (ExtensionData is null) throw new InvalidOperationException();
			else
			{
				return ((ulong)ExtensionType).ToBytes(2)
					.Concat(((ulong)ExtensionData.Length).ToBytes(2))
					.Concat(ExtensionData)
					.ToArray();
			}
		}
	}
}