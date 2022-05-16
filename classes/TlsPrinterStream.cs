using System.Net.Sockets;
using System.Text;
using TlsObjectModel;

namespace TlsPrinter
{
	public class TlsPrinterStream : Stream
	{
		bool HandshakeComplete = false;
		TlsPlaintext? OriginalRecord { get; set; }
		System.Random rng;
		NetworkStream tcpStream;
		public string? JA3 { get; }
		public TlsPrinterSettings Settings { get; set; }
		public override bool CanRead => tcpStream.CanRead;
		public override bool CanSeek => tcpStream.CanSeek;
		public override bool CanTimeout => tcpStream.CanTimeout;
		public override bool CanWrite => tcpStream.CanWrite;
		public override long Length => tcpStream.Length;
		public override long Position
		{
			get => tcpStream.Position;
			set => throw new NotImplementedException();
		}
		public TlsPrinterStream(NetworkStream innerStream, TlsPrinterSettings? settings = null)
		{
			tcpStream = innerStream;
			rng = new System.Random();
			if (settings is null) settings = new();
			Settings = settings;
		}
		/// <summary>
		///
		/// </summary>
		/// <remarks>
		///
		/// </remarks>
		/// <seealso href="https://tls13.ulfheim.net"/>
		/// <seealso href="https://tls12.ulfheim.net"/>
		/// <returns></returns>
		public byte[] CreateClientHello()
		{
			byte[] recordHeader = new byte[] { 0x16, 0x03, 0x01 };
			byte[] recordLength = new byte[2];
			byte[] handshakeHeader = new byte[] { 0x01 };
			byte[] handshakeLength = new byte[3];
			byte[] clientVersion = new byte[] { 0x03, 0x03 };
			byte[] clientRandom = new byte[32];
			byte[] sessionId = new byte[33];
			byte[] cipherSuites = new byte[] { 0, 8, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0, 0xff };
			byte[] compressionMethods = new byte[] { 1, 0 };
			byte[] extensionsLength = new byte[] { 0, 0 };

			return new byte[0];
		}
		/// <summary>
		///
		/// </summary>
		/// <param name="array"></param>
		/// <param name="start"></param>
		/// <param name="length"></param>
		public override void Write(byte[] array, int start, int length)
		{
			if (HandshakeComplete)
			{
				tcpStream.Write(array, start, length);
			}
			else
			{
				if (OriginalRecord is null) OriginalRecord = new TlsPlaintext(array);
				else if (OriginalRecord.NeedsBytes()) OriginalRecord.AddBytes(array);
				if (!OriginalRecord.NeedsBytes())
				{
					if (OriginalRecord.type != ContentType.handshake)
						throw new InvalidOperationException("Not the beginning of a TLS handshake");
					tcpStream.Write(OriginalRecord.ToBytes());
					if (OriginalRecord.HasExtraBytes())
					{
						tcpStream.Write(OriginalRecord.GetExtraBytes());
					}
					HandshakeComplete = true;
				}
			}
		}
		public override int Read(byte[] buffer, int offset, int count)
		{
			return tcpStream.Read(buffer, offset, count);
		}
		public override void SetLength(long value)
		{
			throw new NotImplementedException();
		}
		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}
		public override void Flush()
		{
			tcpStream.Flush();
		}
		public static byte[] GetHttpMessage(Uri uri)
		{
			ArgumentNullException.ThrowIfNull(uri);
			string body = @"Email=chjones@aleph0.com&password=NotMyActualPassword!";
			byte[] bodyBytes = Encoding.ASCII.GetBytes(body);
			Dictionary<string, string> headers = new() {
				{ "Content-Type", "application/x-www-form-urlencoded" },
				{ "Content-Length", bodyBytes.Length.ToString() },
				{ "Host", uri.IdnHost },
			};
			string greeting = $"POST {uri.AbsoluteUri} HTTP/1.1\n";
			byte[] greetingBytes = System.Text.Encoding.ASCII.GetBytes(greeting);
			byte[] headersBytes = new byte[0];
			foreach (KeyValuePair<string, string> entry in headers)
			{
				byte[] keyBytes = System.Text.Encoding.ASCII.GetBytes($"{entry.Key}: ");
				byte[] valueBytes = System.Text.Encoding.Latin1.GetBytes($"{entry.Value}\n");
				byte[] headerBytes = keyBytes.Concat(valueBytes).ToArray();
				headersBytes = headersBytes.Concat(headerBytes).ToArray();
			}
			headersBytes = headersBytes.Concat(System.Text.Encoding.ASCII.GetBytes("\n")).ToArray();
			byte[] message = greetingBytes.Concat(headersBytes).Concat(bodyBytes).ToArray();
			return message;
		}
		public static void TestHttp(Uri uri, Stream stream)
		{
			stream.Write(TlsPrinterStream.GetHttpMessage(uri));
			byte[] responseBytes = new byte[1024];
			int responseLength = stream.Read(responseBytes, 0, 1024);
			string response = System.Text.Encoding.ASCII.GetString(responseBytes, 0, responseLength);
			Console.Write(response);
		}
	}
}