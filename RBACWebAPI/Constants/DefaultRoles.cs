using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace RBACWebAPI.Constants
{
    public class DefaultRoles
    {
        public const string SuperAdmin = "SuperAdmin";
        public const string Admin = "Admin";
        public const string Moderator = "Moderator";
        public const string Basic = "Basic";

        public static List<IdentityRole> GetDefaultRoles()
        {
            var roles = new List<IdentityRole>
            {
                new IdentityRole(SuperAdmin),
                new IdentityRole(Admin),
                new IdentityRole(Moderator),
                new IdentityRole(Basic)
            };
            return roles;
        }

        public static List<Claim> GetDefaultRoleClaims()
        {
            var roles = GetDefaultRoles();
            var claims = roles.Select(role => new Claim(ClaimTypes.Role, role.Name)).ToList();
            return claims;
        }
    }
}
