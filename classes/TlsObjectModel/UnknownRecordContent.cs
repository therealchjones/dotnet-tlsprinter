namespace TlsObjectModel
{
	public class UnknownRecordContent : RecordContent
	{
		public UnknownRecordContent(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override void FromBytes(byte[] bytes)
		{
			if (BackingBytes is not null && BackingBytes.Length != 0)
			{
				throw new InvalidOperationException();
			}
			BackingBytes = bytes;
		}
		public override void AddBytes(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public override byte[] ToBytes()
		{
			return GetRawData();
		}
	}
}
