using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OAuthSample.Data;
using OAuthSample.Entities;
using OAuthSample.Models;

namespace OAuthSample.Services
{
    public class AuthService(AppDBContext context, IConfiguration configuration) : IAuthService
    {
        
        public async Task<TokenResponseDto?> LoginAsync(UserDto request)
        {
            User user = new User();
            user = context.Users.FirstOrDefaultAsync(u => u.Name == request.Name).Result;

            if (user is null)
            {
                return null;
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return null;
            }

            TokenResponseDto TokenResponce = await CreateTokenResponce(user);
            return (TokenResponce);
        }

        private async Task<TokenResponseDto> CreateTokenResponce(User user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshToken(user)
            };
        }

        public async Task<User?> RegisterUserAsync(UserDto request)
        {
            if(await context.Users.AnyAsync<User>(u => u.Name == request.Name))
            {
                return null;
            }
           
            User user = new User();
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            user.Id = Guid.NewGuid();
            user.Name = request.Name;
            user.PasswordHash = hashedPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<TokenResponseDto?> RefreshTokens(RefreshTokenRequestDto refreshTokenRequest)
        {
            var user = await ValadateRefreshTokenAsync(refreshTokenRequest.UserId, refreshTokenRequest.RefreshToken);

            if(user is null)
            {
                return null;
            }

            return await CreateTokenResponce(user);
        }

        private async Task<User> ValadateRefreshTokenAsync(Guid userId, string refreshToken)
        {
            var user = await context.Users.FindAsync(userId);

            if(user == null|| user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }

            return user;
        }

        private string CreateToken(User user)
        {
            GenerateAndSaveRefreshToken(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role),
             };
            
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescripter = new JwtSecurityToken(
                issuer: configuration.GetValue<String>("AppSettings:Issuer"), // who is issuing the token
                audience: configuration.GetValue<String>("AppSettings:Audience"),// users using the token
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(tokenDescripter);
        }

        private string GenerateToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> GenerateAndSaveRefreshToken(User user){
            user.RefreshToken = GenerateToken();
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);

            context.SaveChangesAsync();
            return user.RefreshToken;
        } 
    }
}
