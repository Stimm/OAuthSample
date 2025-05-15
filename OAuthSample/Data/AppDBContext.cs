using Microsoft.EntityFrameworkCore;
using OAuthSample.Entities;

namespace OAuthSample.Data
{
    public class AppDBContext(DbContextOptions<AppDBContext> options): DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
