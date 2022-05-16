namespace TlsObjectModel
{
	internal static class TlsUtils
	{
		public static ulong BytesToUInt64(byte[] bytes)
		{
			if (bytes.Length > 8) throw new ArgumentException();
			bytes = new byte[8 - bytes.Length].Concat(bytes).ToArray();
			if (BitConverter.IsLittleEndian) bytes = bytes.Reverse().ToArray();
			return BitConverter.ToUInt64(bytes);
		}
	}

}