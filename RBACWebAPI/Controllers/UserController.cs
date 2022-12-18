using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RBACWebAPI.Models;
using System.Threading.Tasks;
using System;
using System.Transactions;
using Microsoft.AspNetCore.Rewrite;
using RBACWebAPI.Constants;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RBACWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterUserVM model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null) return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Already Exists" });
            var user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.UserName
            };

            var defaultRoles = DefaultRoles.GetDefaultRoles();

            try
            {
                using (var scope = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
                {
                    var roleExist = await _roleManager.RoleExistsAsync(defaultRoles[3].ToString());
                    if (!roleExist) await _roleManager.CreateAsync(new IdentityRole(defaultRoles[3].ToString()));
                    await _userManager.CreateAsync(user, model.Password);
                    await _userManager.AddToRoleAsync(user, defaultRoles[3].ToString());
                    scope.Complete();

                    return Ok(new Response { Status = "Success", Message = "User Created Succesfully" });
                }
            }
            catch (TransactionAbortedException ex) { return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = ex.Message }); }
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginUserVM model)
        {
            var defaultRoles = DefaultRoles.GetDefaultRoles();

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Role, defaultRoles[3].ToString())
                };

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("7S79jvOkEdwoRqHx"));
                var token = new JwtSecurityToken(
                    issuer: "https://dotnetdetail.net",
                    audience: "https://dotnetdetail.net",
                    expires: DateTime.Now.AddDays(5),
                    claims: authClaims,
                    signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

    }
}
