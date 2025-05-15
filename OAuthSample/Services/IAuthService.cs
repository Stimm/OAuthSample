using OAuthSample.Entities;
using OAuthSample.Models;

namespace OAuthSample.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterUserAsync(UserDto request);
        Task<TokenResponseDto> LoginAsync(UserDto request);
        Task<TokenResponseDto> RefreshTokens(RefreshTokenRequestDto refreshTokenRequest);
    }
}
