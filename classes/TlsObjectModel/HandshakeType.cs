namespace TlsObjectModel
{
	public enum HandshakeType : byte
	{
		hello_request_RESERVED = 0,
		client_hello = 1,
		server_hello = 2,
		hello_verify_request_RESERVED = 3,
		new_session_ticket = 4,
		end_of_early_data = 5,
		encrypted_extensions = 8,
		certificate = 11,
		certificate_request = 13,
		certificate_verify = 15,
		finished = 20,
		key_update = 24,
		message_hash = 254
	}
}