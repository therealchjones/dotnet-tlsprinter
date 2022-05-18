namespace TlsObjectModel
{
	public class UnknownExtension : Extension
	{
		byte ExtensionType;
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
			BackingBytes = BackingBytes.Concat(bytes).ToArray();
			if (BackingBytes.Length > 0) ExtensionType = BackingBytes[0];
		}
		public override byte[] ToBytes()
		{
			if (BackingBytes is null) throw new InvalidOperationException();
			else return BackingBytes;
		}
	}
}