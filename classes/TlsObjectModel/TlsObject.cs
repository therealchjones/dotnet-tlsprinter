namespace TlsObjectModel
{
	public abstract class TlsObject
	{
		protected byte[]? BackingBytes { get; set; }
		public abstract void AddBytes(byte[] bytes);
		public void AddBytes(IEnumerable<byte> bytes)
		{
			AddBytes(bytes.ToArray<byte>());
		}
		public abstract byte[] ToBytes();
		public abstract void FromBytes(byte[] bytes);
		public bool HasRawData()
		{
			return BackingBytes is not null;
		}
		public byte[] GetRawData()
		{
			if (BackingBytes is null) throw new InvalidOperationException();
			else return BackingBytes;
		}
	}

}