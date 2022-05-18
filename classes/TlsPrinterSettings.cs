using System.Net.Security;
using System.Security.Authentication;
using TlsObjectModel;

namespace TlsPrinter
{
	public class TlsPrinterSettings
	{
		public List<SslProtocols>? Versions { get; set; }
		public SslProtocols? ClientVersion { get; set; }
		public List<TlsCipherSuite>? Ciphers { get; set; }
		public List<Extension>? Extensions { get; set; }
		public List<Curve>? Curves { get; set; }
		public List<PointFormat>? PointFormats { get; set; }
		public SslClientAuthenticationOptions? SslOptions { get; set; }
		public TlsPrinterSettings(SslClientAuthenticationOptions? SslOptions = null)
		{
			if (SslOptions is null) SslOptions = new();
			this.SslOptions = SslOptions;
		}
		public SslClientAuthenticationOptions GetSslOptions()
		{
			if (SslOptions is null) SslOptions = new();
			if (Versions is not null)
			{
				SslProtocols protocols = SslProtocols.None;
				foreach (SslProtocols protocol in Versions)
				{
					protocols = protocols | protocol;
				}
				SslOptions.EnabledSslProtocols = protocols;
			}
			if (Ciphers is not null)
			{
				try
				{
					SslOptions.CipherSuitesPolicy = new(Ciphers);
				}
				catch
				{
					// Not CLS compliant; if this isn't settable it's not needed
				}
			}
			return SslOptions;
		}
		internal ClientHello ToClientHello()
		{
			ClientHello clientHello = new ClientHello();
			clientHello.Random = new byte[32];
			clientHello.legacy_session_id = new byte[32];
			if (Ciphers is not null)
			{
				foreach (TlsCipherSuite cipher in Ciphers)
				{
					clientHello.cipher_suites.Add(new CipherSuite(cipher));
				}
			}
			if (Extensions is not null) clientHello.Extensions = Extensions;
			// if (Curves is not null) clientHello.Curves = Curves;
			// if (PointFormats is not null) clientHello.PointFormats = PointFormats;
			return clientHello;
		}
	}
}