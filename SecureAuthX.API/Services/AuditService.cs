using SecureAuthX.API.Data;
using SecureAuthX.API.Models;
using SecureAuthX.API.Services.Interfaces;

namespace SecureAuthX.API.Services
{
	public class AuditService : IAuditService
	{
		public readonly ApplicationDbContext _context;

        public AuditService(ApplicationDbContext context)
        {
            _context = context;
        }
        public async Task LogAsync(string email, string action, HttpContext context)
		{
			var log = new AuditLog
			{
				Email = email,
				Action = action,
				Timestamp = DateTime.UtcNow,
				IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
				UserAgent = context.Request.Headers["User-Agent"].ToString(),
			};


			_context.Add(log);
			await _context.SaveChangesAsync();
		}
	}
}
