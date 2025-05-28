using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureAuthX.API.Data;
using SecureAuthX.API.Models;

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

			return Ok("User registered successfully.");
		}


    }
}
