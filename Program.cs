using System.Net.Security;
using System.Net.Sockets;
using TlsPrinter;

string url = "https://httpbin.org/post";

Uri uri = new(url);

Socket tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
tcpSocket.Connect(uri.IdnHost, uri.Port);
NetworkStream tcpStream = new(tcpSocket, true);
SslClientAuthenticationOptions sslOptions = new() { TargetHost = uri.IdnHost };
TlsPrinterSettings tlsSettings = new(sslOptions);
TlsPrinterStream tlsStream = new(tcpStream, tlsSettings);
SslStream sslStream = new(tlsStream);
sslStream.AuthenticateAsClient(sslOptions);

TlsPrinterStream.TestHttp(uri, sslStream);
