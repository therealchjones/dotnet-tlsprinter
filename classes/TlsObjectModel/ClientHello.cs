using System.Net.Security;
using System.Security.Authentication;

namespace TlsObjectModel
{
	public class ClientHello : TlsObject
	{
		ProtocolVersion legacy_version = new(new byte[] { 3, 3 });
		public SslProtocols ClientVersion;
		public byte[]? Random;
		public byte[]? legacy_session_id;
		public List<TlsCipherSuite>? cipher_suites;
		public byte[]? legacy_compression_methods;
		public List<Extension>? Extensions;
		public List<Curve>? Curves;
		public List<PointFormat>? PointFormats;
		public override void FromBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override void AddBytes(byte[] bytes)
		{
			throw new NotImplementedException();
		}
		public override byte[] ToBytes()
		{
			List<byte[]> handshakeBuilder = new();
			List<byte[]> messageBuilder = new();
			messageBuilder.Add(new byte[] { 0x16, 3, 1 });
			byte[] recordHeader = new byte[] { 0x16, 0x03, 0x01, 0x00, 0x00 };
			byte[] handshakeHeader = new byte[] { 0x01, 0x00, 0x00, 0x00 };
			byte[] clientVersion = new byte[] { 0x03, 0x03 };
			byte[] clientRandom = new byte[32];
			//rng.NextBytes(clientRandom);
			byte[] sessionId = new byte[33];
			//rng.NextBytes(sessionId);
			sessionId[0] = 32;
			byte[] cipherSuites = new byte[] { 0, 8, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0, 0xff };
			byte[] compressionMethods = new byte[] { 1, 0 };
			byte[] extensionsLength = new byte[] { 0, 0 };

			return new byte[0];
		}
	}
}