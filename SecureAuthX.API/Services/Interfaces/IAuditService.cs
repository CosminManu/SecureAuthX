namespace SecureAuthX.API.Services.Interfaces
{
    public interface IAuditService
    {
        Task LogAsync(string email, string action, HttpContext context);
    }
}
