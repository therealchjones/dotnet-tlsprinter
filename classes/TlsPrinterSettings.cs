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
		public List<TlsExtension>? Extensions { get; set; }
		public List<TlsCurve>? Curves { get; set; }
		public List<TlsPointFormat>? PointFormats { get; set; }
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
	}

}