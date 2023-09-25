using JWTAuthentication.DTO;

namespace JWTAuthentication.Services
{
    public interface IAuthService
    {
        Task<AuthReturnDTO> Register(RegisterDTO model);
        Task<AuthReturnDTO> LogIn(LogInDTO model);
    }
}
