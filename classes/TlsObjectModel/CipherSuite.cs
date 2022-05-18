using System.Net.Security;

namespace TlsObjectModel
{
	public class CipherSuite : TlsObject
	{
		TlsCipherSuite? cipher;
		public CipherSuite(byte[] bytes)
		{
			FromBytes(bytes);
		}
		public CipherSuite(TlsCipherSuite cipher)
		{
			ArgumentNullException.ThrowIfNull(cipher);
			this.cipher = cipher;
		}
		public override void FromBytes(byte[] bytes)
		{
			ArgumentNullException.ThrowIfNull(bytes);
			if (bytes.Length != 2) throw new ArgumentException();
			BackingBytes = bytes;
			cipher = null;
			if (BackingBytes[0] == 0x13)
			{
				switch (BackingBytes[1])
				{
					case 1:
						cipher = TlsCipherSuite.TLS_AES_128_GCM_SHA256;
						break;
					case 2:
						cipher = TlsCipherSuite.TLS_AES_256_GCM_SHA384;
						break;
					case 3:
						cipher = TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256;
						break;
					case 4:
						cipher = TlsCipherSuite.TLS_AES_128_CCM_SHA256;
						break;
					case 5:
						cipher = TlsCipherSuite.TLS_AES_128_CCM_8_SHA256;
						break;
				}
			}
		}
		public override void AddBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override byte[] ToBytes()
		{
			if (cipher is null)
			{
				if (BackingBytes is null || BackingBytes.Length != 2) throw new InvalidOperationException();
				return BackingBytes;
			}
			byte[] bytes = new byte[2] { 0x13, 0 };
			switch (cipher)
			{
				case TlsCipherSuite.TLS_AES_128_GCM_SHA256:
					bytes[1] = 1;
					break;
				case TlsCipherSuite.TLS_AES_256_GCM_SHA384:
					bytes[1] = 2;
					break;
				case TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
					bytes[1] = 3;
					break;
				case TlsCipherSuite.TLS_AES_128_CCM_SHA256:
					bytes[1] = 4;
					break;
				case TlsCipherSuite.TLS_AES_128_CCM_8_SHA256:
					bytes[1] = 5;
					break;
			}
			if (bytes[1] == 0)
			{
				if (BackingBytes is null || BackingBytes.Length != 2) throw new InvalidOperationException();
				return BackingBytes;
			}
			return bytes;
		}
	}
}