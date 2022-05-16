namespace TlsObjectModel
{
	/// <summary>
	/// Represents the types of messages to be sent at the TLS Record Layer
	/// </summary>
	public enum ContentType : byte
	{
		invalid = 0,
		change_cipher_spec = 20,
		alert = 21,
		handshake = 22,
		application_data = 23,
		heartbeat = 24
	}

}