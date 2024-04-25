using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.InteropServices;

namespace ASM.Models
{
    public class JobApplication
    {
        public int JobApplicationId { get; set; }
        public DateTime ApplicationDate { get; set; }
        public string? CoverLetter { get; set; }
        [NotMapped]
        public IFormFile CoverLetterFile { get; set; }
        public string ApplicationStatus { get; set; }
        public int JobSeekerId { get; set; }
        public int JobListingId { get; set; }
        public virtual JobSeeker? Seekers { get; set; }
        public virtual JobListing? Listing { get; set; }
        //public virtual Employer? Employer { get; set; }
    }
}
