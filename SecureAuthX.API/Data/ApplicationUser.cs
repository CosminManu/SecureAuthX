using Microsoft.AspNetCore.Identity;

namespace SecureAuthX.API.Data
{
	public class ApplicationUser : IdentityUser
	{
		public string FullName { get; set; } = string.Empty;
		public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
	}
}
