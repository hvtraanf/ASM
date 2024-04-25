using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using ASM.Data;
using ASM.Models;
using Microsoft.AspNetCore.Authorization;

namespace ASM.Controllers
{
    public class JobListingsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public JobListingsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: JobListings
        public async Task<IActionResult> Index()
        {

            // get user role
            var role = User.Claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")?.Value;
            // my user id
            var userId = User.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
            var jobListings = _context.JobListing
                .Where(x => x.Approved)
                .Include(j => j.Employer)                
                .ToList();

            if (role== "EMPLOYER")
            {                
                var emp = _context.Employer.Where(x => x.UserId == userId).FirstOrDefault();
                jobListings = jobListings.Where(x => x.EmployerId == emp.EmployerId).ToList();
            }




            try
            {
                if (Request.Query["jobtitle"] != "")
                {
                    jobListings = jobListings.Where(x => x.JobTitle.Contains(Request.Query["jobtitle"])).ToList();
                }
                
                jobListings = jobListings.Where(x => x.JobTitle.Contains(Request.Query["jobcategory"])).ToList();
            }
            catch (Exception)
            {

                //throw;
            }
            return View(jobListings);
        }

        // GET: JobListings/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobListing = await _context.JobListing
                .Include(j => j.Employer)
                .Include(j => j.JobApplications)
                //.Include(j => j.JobSeeker)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (jobListing == null)
            {
                return NotFound();
            }

            return View(jobListing);
        }

        [Authorize(Roles = "EMPLOYER")]
        // GET: JobListings/ManageJobApplication
        public async Task<IActionResult> ManageJobApplication(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobApplications = await _context.JobApplication.FindAsync(id);
            if (jobApplications == null)
            {
                return NotFound();
            }
            //ViewData["EmployerId"] = new SelectList(_context.Employer, "EmployerId", "EmployerId", jobApplications.JobApplicationId);
            return View(jobApplications);
        }

        [Authorize(Roles = "EMPLOYER")]
        // POST: JobListings/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageJobApplication(int id, [Bind("JobApplicationId, ApplicationStatus")] JobApplication jobApplication)
        {
            if (id != jobApplication.JobApplicationId)
            {
                return NotFound();
            }

            var jobApp = _context.JobApplication.Find(jobApplication.JobApplicationId);

            jobApp.ApplicationStatus = jobApplication.ApplicationStatus;
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

            [Authorize(Roles = "EMPLOYER")]
        // GET: JobListings/Create
        public IActionResult Create()
        {
            ViewData["EmployerId"] = new SelectList(_context.Employer, "EmployerId", "EmployerId");
            return View();
        }

        [Authorize(Roles = "EMPLOYER")]
        // POST: JobListings/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,JobTitle,JobDescription,JobRequirement,JobType,EmployerId,ApplicationDeadline")] JobListing jobListing)
        {
            if (ModelState.IsValid)
            {
                var userId = User.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;
                var emp = _context.Employer.Where(x => x.UserId == userId).FirstOrDefault();
                jobListing.EmployerId = emp.EmployerId;
                _context.Add(jobListing);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            //ViewData["EmployerId"] = new SelectList(_context.Employer, "EmployerId", "EmployerId", jobListing.EmployerId);
            return View(jobListing);
        }

        [Authorize(Roles = "EMPLOYER")]
        // GET: JobListings/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobListing = await _context.JobListing.FindAsync(id);
            if (jobListing == null)
            {
                return NotFound();
            }
            ViewData["EmployerId"] = new SelectList(_context.Employer, "EmployerId", "EmployerId", jobListing.EmployerId);
            return View(jobListing);
        }

        [Authorize(Roles = "EMPLOYER")]
        // POST: JobListings/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,JobTitle,JobDescription,JobRequirement,JobType,EmployerId,ApplicationDeadline")] JobListing jobListing)
        {
            if (id != jobListing.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(jobListing);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!JobListingExists(jobListing.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            ViewData["EmployerId"] = new SelectList(_context.Employer, "EmployerId", "EmployerId", jobListing.EmployerId);
            return View(jobListing);
        }

        [Authorize(Roles = "EMPLOYER")]
        // GET: JobListings/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobListing = await _context.JobListing
                .Include(j => j.Employer)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (jobListing == null)
            {
                return NotFound();
            }

            return View(jobListing);
        }

        [Authorize(Roles = "EMPLOYER")]
        // POST: JobListings/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var jobListing = await _context.JobListing.FindAsync(id);
            if (jobListing != null)
            {
                _context.JobListing.Remove(jobListing);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool JobListingExists(int id)
        {
            return _context.JobListing.Any(e => e.Id == id);
        }
    }
}
