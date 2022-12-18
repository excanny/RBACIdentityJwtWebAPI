using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;

namespace RBACWebAPI.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions options)
    : base(options)
        {
        }
       
    //    public DbSet<Company> Companies { get; set; }
    //    public DbSet<Employee> Employees { get; set; }
    }
}
