using System.Net.Security;
using System.Net.Sockets;
using TlsPrinter;

string url = "https://httpbin.org/post";
url = "https://android.clients.google.com/auth";

Uri uri = new(url);

Socket tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
tcpSocket.Connect(uri.IdnHost, uri.Port);
NetworkStream tcpStream = new(tcpSocket, true);
CipherSuitesPolicy ciphers = new CipherSuitesPolicy(new List<TlsCipherSuite>(){
	TlsCipherSuite.TLS_AES_256_GCM_SHA384,
	TlsCipherSuite.TLS_AES_128_GCM_SHA256,
	TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
	TlsCipherSuite.TLS_AES_128_CCM_SHA256,
	TlsCipherSuite.TLS_AES_128_CCM_8_SHA256,
});

SslClientAuthenticationOptions sslOptions = new()
{
	TargetHost = uri.IdnHost,
	//CipherSuitesPolicy = ciphers,
	EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
};
TlsPrinterSettings tlsSettings = new(sslOptions);
TlsPrinterStream tlsStream = new(tcpStream, tlsSettings);
SslStream sslStream = new(tlsStream);
sslStream.AuthenticateAsClient(sslOptions);

TlsPrinterStream.TestHttp(uri, sslStream);
