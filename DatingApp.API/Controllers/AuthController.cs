using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            //TODO: validate request

            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
            var isUserExist = await _repo.UserExists(userForRegisterDto.Username);
            if (isUserExist) return BadRequest("Username already exists");
            var userToCreate = new User()
            {
                Username = userForRegisterDto.Username
            };

            var createdUser = await _repo.Register(userToCreate, userForRegisterDto.Password);
            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForRegisterDto)
        {
            var userFromRepo = await _repo.Login(userForRegisterDto.Username.ToLower(), userForRegisterDto.Password);
            if (userFromRepo == null) return Unauthorized();

            var claims = createClaims(userFromRepo);
            var expireDate = DateTime.Now.AddDays(1);
            var creds = createCredentials();

            var tokenDescriptor = new SecurityTokenDescriptor() { Subject = claims, Expires = expireDate, SigningCredentials = creds };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new { token = tokenHandler.WriteToken(token) });
        }

        private SigningCredentials createCredentials()
        {
            var key = _config.GetSection("AppSettings:Token").Value;
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);
            return creds;
        }

        private ClaimsIdentity createClaims(User userFromRepo)
        {
            var userIdClaim = new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString());
            var usernameClaim = new Claim(ClaimTypes.Name, userFromRepo.Username);
            var claims = new Claim[] { userIdClaim, usernameClaim };
            var claimsIdentity = new ClaimsIdentity(claims);
            return claimsIdentity;
        }
    }
}