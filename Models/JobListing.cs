namespace ASM.Models
{
    public class JobListing
    {
        public int Id { get; set; }
        public string JobTitle { get; set; }
        public string JobDescription { get; set; }
        public string JobRequirement {  get; set; }
        public string JobType { get; set; }
        public string EmployerId { get; set; }
        public DateTime ApplicationDeadline { get; set; }
        public bool Approved { get; set; }
        public virtual Employer? Employer { get; set; }
        //public virtual JobSeeker? JobSeeker { get; set; }
        public virtual ICollection<JobApplication>? JobApplications { get; set; }
    }
}
