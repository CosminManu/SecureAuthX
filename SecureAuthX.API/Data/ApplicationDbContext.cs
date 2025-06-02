using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using SecureAuthX.API.Models;


namespace SecureAuthX.API.Data
{
	public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
	{
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) 
			: base(options) { }

		public DbSet<AuditLog> AuditLogs { get; set; }
	}
}
