﻿namespace SecureAuthX.API.Models
{
	public class AuditLog
	{
		public int Id { get; set; }
		public string Email { get; set; } = string.Empty;
		public string Action { get; set; } = string.Empty;

		public DateTime Timestamp { get; set; }

		public string IpAddress { get; set; } = string.Empty;

		public string UserAgent {  get; set; } = string.Empty;
	}
}
