using Microsoft.AspNetCore.Identity;

namespace ASM.Models
{
    public class Employer
    {
        public string EmployerId { get; set; }
        public string CompanyName { get; set; }
        public string ContactEmail { get; set; }
        public string UserId { get; set; }
        public virtual IdentityUser? User { get; set; }
        public virtual ICollection<JobListing>? JobListing { get; set; }
    }
}
