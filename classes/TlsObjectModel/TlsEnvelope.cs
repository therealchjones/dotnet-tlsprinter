namespace TlsObjectModel
{
	/// <summary>
	/// Represents a <see cref="TlsObject"/> designed to deliver another <see cref="TlsObject"/>.
	/// </summary>
	public abstract class TlsEnvelope : TlsObject
	{
		/// <summary>
		/// Represents the length of the encapsulated <see cref="TlsObject"/>
		/// </summary>
		/// <remarks>Using the same notation as the TLS specification, <see
		/// cref="Length"/> is the number of bytes of content being delivered in
		/// this <see cref="TlsEnvelope"/>, not the size of the <see
		/// cref="TlsEnvelope"/> itself, which includes additional
		/// overhead.</remarks>
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
