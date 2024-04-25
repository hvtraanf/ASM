using Microsoft.AspNetCore.Identity;

namespace ASM.Models
{
    public class JobSeeker
    {
        public int JobSeekerId { get; set; }
        public string Fullname { get; set; }
        public string Email { get; set; }
        public string UserId { get; set; }
        public virtual IdentityUser? User { get; set; }
        public virtual ICollection<JobApplication>? Application { get; set; }
    }
}
