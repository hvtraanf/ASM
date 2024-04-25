using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ASM.Models;
using Microsoft.AspNetCore.Identity;

namespace ASM.Data
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser, IdentityRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        public DbSet<ASM.Models.Employer> Employer { get; set; } = default!;
        public DbSet<ASM.Models.JobSeeker> JobSeeker { get; set; } = default!;
        public DbSet<ASM.Models.JobListing> JobListing { get; set; } = default!;
        public DbSet<ASM.Models.JobApplication> JobApplication { get; set; } = default!;
        

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Employer>()
                .HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId);

            modelBuilder.Entity<JobSeeker>()
                .HasOne(j => j.User)
                .WithMany()
                .HasForeignKey(j => j.UserId);

            base.OnModelCreating(modelBuilder);
        }
    }
}
