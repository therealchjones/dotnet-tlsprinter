using System.Net.Security;
using System.Security.Authentication;

namespace TlsPrinter
{

	public static class TlsPrinterExtensions
	{
		public static byte[] ToBytes(this SslProtocols version)
		{
			switch (version)
			{
				case SslProtocols.Tls: return new byte[] { 3, 1 };
				case SslProtocols.Tls11: return new byte[] { 3, 2 };
				case SslProtocols.Tls12: return new byte[] { 3, 3 };
				case SslProtocols.Tls13: return new byte[] { 3, 4 };
				default: throw new NotSupportedException();
			}
		}
		public static byte[] ToBytes(this TlsCipherSuite cipherSuite)
		{
			switch (cipherSuite)
			{
				case TlsCipherSuite.TLS_AES_128_GCM_SHA256: return new byte[] { 0x13, 1 };
				case TlsCipherSuite.TLS_AES_256_GCM_SHA384: return new byte[] { 0x13, 2 };
				case TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256: return new byte[] { 0x13, 3 };
				default: throw new NotSupportedException();
			}
		}
		public static byte[] ToBytes(this ushort uint16)
		{
			byte[] uint16bytes = BitConverter.GetBytes(uint16);
			if (BitConverter.IsLittleEndian) uint16bytes = uint16bytes.Reverse().ToArray();
			return uint16bytes;
		}
		public static ushort ToUInt16(this byte[] uint16bytes)
		{
			if (uint16bytes.Length != 2) throw new ArgumentOutOfRangeException();
			if (BitConverter.IsLittleEndian) uint16bytes = uint16bytes.Reverse().ToArray();
			return BitConverter.ToUInt16(uint16bytes);
		}
	}

}