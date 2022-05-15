namespace TlsObjectModel
{
	public abstract class TlsEnvelope : TlsObject
	{
		protected ulong? Length;
		protected byte[]? ExtraBytes { get; set; }
		protected byte[]? PendingBytes { get; set; }
		protected byte[] GetLengthBytes()
		{
			if (Length is null) throw new InvalidOperationException("Length is not defined.");
			else return ((ulong)Length).ToBytes(this.GetType().GetLengthFieldLength());
		}
		protected void SetLength(byte[] bytes)
		{
			Length = this.GetType().GetLength(bytes);
		}
	}
}
