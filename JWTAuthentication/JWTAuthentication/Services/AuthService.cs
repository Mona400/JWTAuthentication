using JWTAuthentication.DTO;
using JWTAuthentication.Helpers;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NuGet.Packaging;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Services
{
    public class AuthService:IAuthService
    {
        private readonly UserManager<Client> _userManager;
        private readonly JWT _jwt;
        public AuthService(UserManager<Client> userManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
        }
        public async Task<AuthReturnDTO> LogIn(LogInDTO model)
        {
            var authModel = new AuthReturnDTO();
            var user = await _userManager.FindByNameAsync(model.UserName) ;
            if (user == null)
            {
                authModel.Message = "UserName Is InCorrect !!";
                return authModel;
            }
            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Password Is InCorrect !!";
                return authModel;
            }
            var JwtSecurityToken = await GenerateJwtToken(user);

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken);
            authModel.Email = user.Email;
            authModel.UserName = user.UserName;


            return authModel;
        }
        public async Task<AuthReturnDTO> Register(RegisterDTO model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthReturnDTO { Message = "Email Is Already Exist !" };

            if (await _userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthReturnDTO { Message = "UserName Is Already Exist !" };
            var user = new Client
            {
                UserName = model.UserName,
                Email = model.Email,
                Name= model.Name,
              PasswordHash= model.Password,
            };
            var res = await _userManager.CreateAsync(user, model.Password); // Pass the plain-text password here

            if (!res.Succeeded)
            {
                var errors = string.Empty;
                foreach (var item in res.Errors)
                {
                    errors += $"{item.Description} ,";
                }
                return new AuthReturnDTO { Message = "Password must Contains Captial , Small Letter Number & Spectial Caracter" };
            }

            //await _userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await GenerateJwtToken(user);

            return new AuthReturnDTO
            {
                IsAuthenticated = true,
                Email = user.Email,
                UserName = user.UserName,
                Message = "Registration Done Successfully",
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),

                //Default  Values


            };
        }

        private async Task<JwtSecurityToken> GenerateJwtToken( Client client)
        {
            //UserClaims
            var userClaim = _userManager.GetClaimsAsync(client);
            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Sub,client.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub,client.Email),
                new Claim(JwtRegisteredClaimNames.Sub,client.Name),
            };
            claims.AddRange(await userClaim);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredential = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(

                issuer: _jwt.Issure,
                audience: _jwt.Audience,
                claims: claims,
                signingCredentials: signingCredential


                );
            return jwtSecurityToken;

            //UserRoles
            //var userRole=_userManager.GetRolesAsync(client);
            ////RolesClaim
            //var roleClaim = new List<Claim>();
            //foreach (var role in userRole.ToString)
            //{
            //    roleClaim.Add(new Claim("role", role));
            //}
        }

       

    }
}
