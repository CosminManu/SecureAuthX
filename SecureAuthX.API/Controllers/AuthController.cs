using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SecureAuthX.API.Data;
using SecureAuthX.API.Models;
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

        public AuthController(UserManager<ApplicationUser> userManager, IConfiguration config)
        {
			_userManager = userManager;
			_config = config;
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
				return BadRequest(result.Errors);
			}

			await _userManager.AddToRoleAsync(user, "User");

			return Ok("User registered successfully.");
		}

		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
		{
			var user = await _userManager.FindByEmailAsync(loginDto.Email);

			if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
			{
				return Unauthorized("Invalid credentials");
			}

			var token = GenerateJwtToken(user);

			return Ok(new { token });
		}

		[Authorize]
		[HttpGet("me")]
		public async Task<IActionResult> GetMe()
		{
			var email = User.FindFirstValue(ClaimTypes.Email);
			var user = await _userManager.FindByEmailAsync(email);

			return Ok(new {user.FullName, user.Email});
		}


		[Authorize(Roles = "Admin")]
		[HttpPost("assign-role")]
		public async Task<IActionResult> AssignRole([FromBody] AssignRoleDto roleDto)
		{
			var user = await _userManager.FindByEmailAsync(roleDto.Email);
			if (user == null)
			{
				return NotFound("User not found.");
			}
			var result = await _userManager.AddToRoleAsync(user, roleDto.Role);
			if (!result.Succeeded)
			{
				return BadRequest(result.Errors);

			}

			return Ok($"Role '{roleDto.Role}' has been assigned to user {user.Email}.");
		}


		[Authorize(Roles = "Admin")]
		[HttpGet("admin-data")]
		public IActionResult GetAdminData()
		{
			return Ok("This route is only accesible for admins.");
		}

		[AllowAnonymous]
		[HttpGet("ping")]
		public IActionResult Ping()
		{
			return Ok("SecureAuthX API is active");
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
