using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureAuthX.API.Data;
using SecureAuthX.API.Models;
using SecureAuthX.API.Services.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecureAuthX.API.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly IConfiguration _config;
		private readonly IAuditService _auditService;

		public AuthController(UserManager<ApplicationUser> userManager, IConfiguration config, IAuditService auditService)
        {
			_userManager = userManager;
			_config = config;
			_auditService = auditService;
        }

		[HttpPost("register")]
		public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
		{
			var user = new ApplicationUser
			{
				UserName = registerDto.Email,
				Email = registerDto.Email,
				FullName = registerDto.FullName,
			};

			var result = await _userManager.CreateAsync(user, registerDto.Password);

			if (!result.Succeeded)
			{
				await _auditService.LogAsync(registerDto.Email, "Failed registration", HttpContext);
				return BadRequest(result.Errors);
			}

			await _userManager.AddToRoleAsync(user, "User");
			await _auditService.LogAsync(registerDto.Email, "Successful registration", HttpContext);

			return Ok("User registered successfully.");
		}

		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
		{
			var user = await _userManager.FindByEmailAsync(loginDto.Email);

			if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
			{
				await _auditService.LogAsync(loginDto.Email, "Failed login", HttpContext);
				return Unauthorized("Invalid credentials");
			}

			var token = GenerateJwtToken(user);
			await _auditService.LogAsync(loginDto.Email, "Successful login", HttpContext);

			return Ok(new { token });
		}

		[Authorize]
		[HttpGet("me")]
		public async Task<IActionResult> GetMe()
		{
			var email = User.FindFirstValue(ClaimTypes.Email);
			if (string.IsNullOrEmpty(email))
			{
				return Unauthorized("Invalid user context");
			}

			var user = await _userManager.FindByEmailAsync(email);
			if (user == null || string.IsNullOrEmpty(user.Email))
			{
				return Unauthorized("User not found");
			}

			await _auditService.LogAsync(user.Email, "Accessed personal profile", HttpContext);

			return Ok(new {user.FullName, user.Email});
		}


		[Authorize(Roles = "Admin")]
		[HttpPost("assign-role")]
		public async Task<IActionResult> AssignRole([FromBody] AssignRoleDto roleDto)
		{
			var user = await _userManager.FindByEmailAsync(roleDto.Email);
			if (user == null)
			{
				await _auditService.LogAsync(roleDto.Email, "Assign role failed - User not found!", HttpContext);
				return NotFound("User not found.");
			}

			var result = await _userManager.AddToRoleAsync(user, roleDto.Role);
			if (!result.Succeeded)
			{
				await _auditService.LogAsync(roleDto.Email, "Assign role failed", HttpContext);
				return BadRequest(result.Errors);

			}
			
			await _auditService.LogAsync(roleDto.Email, $"Assigned Role: {roleDto.Role}", HttpContext);
			return Ok($"Role '{roleDto.Role}' has been assigned to user {user.Email}.");
		}


		[Authorize(Roles = "Admin")]
		[HttpGet("admin-data")]
		public IActionResult GetAdminData()
		{
			var email = User.FindFirstValue(ClaimTypes.Email);
			if (string.IsNullOrEmpty(email))
			{
				return Unauthorized("Invalid user context");
			}

			_auditService.LogAsync(email, "Accessed Admin Data", HttpContext);
			return Ok("This route is only accesible for admins.");
		}

		[AllowAnonymous]
		[HttpGet("ping")]
		public IActionResult Ping()
		{
			_auditService.LogAsync("Anonymous", "Ping test endpoint hit", HttpContext);
			return Ok("SecureAuthX API is active");
		}

		[Authorize(Roles = "Admin")]
		[HttpGet("audit-logs")]
		public IActionResult GetAuditLogs()
		{
			using var scope = HttpContext.RequestServices.CreateScope();
			var _context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

			var logs = _context.AuditLogs
				.OrderByDescending(l => l.Timestamp)
				.Take(100)
				.ToList();

			return Ok(logs);
		}

		[Authorize(Roles = "Admin")]
		[HttpGet("audit-logs-by-email")]
		public IActionResult GetAuditLogsByEmail([FromQuery] string email)
		{
			if (string.IsNullOrEmpty(email))
			{
				return BadRequest("Email parameter is required.");
			}

			using var scope = HttpContext.RequestServices.CreateScope();
			var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

			var logs = context.AuditLogs
				.Where(l => l.Email == email)
				.OrderByDescending(l => l.Timestamp)
				.ToList();

			return Ok(logs);
		}


		[Authorize(Roles = "Admin")]
		[HttpGet("audit-logs-by-date")]
		public IActionResult GetAuditLogsByDate([FromQuery] DateTime from, [FromQuery] DateTime to)
		{
			if (from == default || to == default || from > to)
			{
				return BadRequest("Invalid or missing date range.");
			}

			using var scope = HttpContext.RequestServices.CreateScope();
			var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

			var logs = context.AuditLogs
				.Where(l => l.Timestamp >= from && l.Timestamp <= to)
				.OrderByDescending(l => l.Timestamp)
				.ToList();

			return Ok(logs);
		}



		private string GenerateJwtToken(ApplicationUser user)
		{
			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.Id),
				new Claim(JwtRegisteredClaimNames.Email, user.Email),
				new Claim(ClaimTypes.Email, user.Email),
			};

			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			var expires = DateTime.Now.AddMinutes(30);

			var token = new JwtSecurityToken(
				issuer: _config["Jwt:Issuer"],
				audience: _config["Jwt:Audience"],
				claims: claims,
				expires: expires,
				signingCredentials: creds
			);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}
	}
}
