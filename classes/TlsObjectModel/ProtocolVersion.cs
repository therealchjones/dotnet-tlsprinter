using System.Security.Authentication;

namespace TlsObjectModel
{



	public struct ProtocolVersion
	{
		byte[] bytes = new byte[2] { 0, 0 };
		public ProtocolVersion(string versionString)
		{
			if (String.IsNullOrEmpty(versionString)) throw new ArgumentException();
			switch (versionString)
			{
				case "1.0":
					bytes[0] = 3;
					bytes[1] = 1;
					break;
				case "1.1":
					bytes[0] = 3;
					bytes[1] = 2;
					break;
				case "1.2":
					bytes[0] = 3;
					bytes[1] = 3;
					break;
				case "1.3":
					bytes[0] = 3;
					bytes[1] = 4;
					break;
				default:
					throw new ArgumentException();
			}
		}
		public ProtocolVersion(byte[] versionBytes)
		{
			if (versionBytes.Length != 2) throw new ArgumentException();
			bytes = versionBytes;
		}
		public ProtocolVersion(SslProtocols versionProtocol)
		{
			switch (versionProtocol)
			{
				case SslProtocols.Tls:
					bytes[0] = 3;
					bytes[1] = 1;
					break;
				case SslProtocols.Tls11:
					bytes[0] = 3;
					bytes[1] = 2;
					break;
				case SslProtocols.Tls12:
					bytes[0] = 3;
					bytes[1] = 3;
					break;
				case SslProtocols.Tls13:
					bytes[0] = 3;
					bytes[1] = 4;
					break;
				default:
					throw new ArgumentException();
			}
		}
		public byte[] ToBytes()
		{
			return bytes;
		}
	}
}
