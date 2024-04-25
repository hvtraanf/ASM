using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using ASM.Data;
using ASM.Models;
using Microsoft.AspNetCore.Hosting;
using System.Security.Claims;

namespace ASM.Controllers
{
    public class JobApplicationsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public JobApplicationsController(ApplicationDbContext context, IWebHostEnvironment webHostEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostEnvironment;
        }

        // GET: JobApplications
        public async Task<IActionResult> Index()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var applicationDbContext = _context.JobApplication
                .Where(x => x.Seekers.UserId == userId)
                .Include(j => j.Listing)
                .Include(j => j.Seekers);

            if (Request.Query["success"] == "1")
            {
                ViewBag.Success = true;
            }
            else
            {
                ViewBag.Success = false;
            }

            return View(await applicationDbContext.ToListAsync());
        }

        // GET: JobApplications/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobApplication = await _context.JobApplication
                .Include(j => j.Listing)
                .Include(j => j.Seekers)
                .FirstOrDefaultAsync(m => m.JobApplicationId == id);
            if (jobApplication == null)
            {
                return NotFound();
            }

            return View(jobApplication);
        }

        // GET: JobApplications/Create
        public IActionResult Create(int id)
        {
            ViewData["JobListingId"] = id; //new SelectList(_context.JobListing, "Id", "Id", id);

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var jobSeeker = _context.JobSeeker.Where(x => x.UserId == userId).FirstOrDefault();
            ViewData["JobSeekerId"] = jobSeeker.JobSeekerId; //new SelectList(_context.JobSeeker, "JobSeekerId", "JobSeekerId");
            return View();
        }

        // POST: JobApplications/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("JobApplicationId,ApplicationDate,CoverLetterFile,ApplicationStatus,JobSeekerId,JobListingId")] JobApplication jobApplication)
        {
            //jobApplication.CoverLetter = "None";
            if (ModelState.IsValid)
            {
                if (jobApplication.CoverLetterFile != null && jobApplication.CoverLetterFile.Length > 0)
                {
                    // Generate a unique file name for the uploaded file
                    var uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(jobApplication.CoverLetterFile.FileName);

                    // Combine the project's uploads directory with the unique file name
                    var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", uniqueFileName);

                    // Save the file to the server
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await jobApplication.CoverLetterFile.CopyToAsync(fileStream);
                    }

                    // Set the CvUrl property of the job application
                    jobApplication.CoverLetter = "/uploads/" + uniqueFileName;
                }

                _context.Add(jobApplication);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index), new {success = 1});
            }

            ViewData["JobListingId"] = new SelectList(_context.JobListing, "Id", "Id", jobApplication.JobListingId);
            return View(jobApplication);
        }

        // GET: JobApplications/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobApplication = await _context.JobApplication.FindAsync(id);
            if (jobApplication == null)
            {
                return NotFound();
            }
            ViewData["JobListingId"] = new SelectList(_context.JobListing, "Id", "Id", jobApplication.JobListingId);
            ViewData["JobSeekerId"] = new SelectList(_context.JobSeeker, "JobSeekerId", "JobSeekerId", jobApplication.JobSeekerId);
            return View(jobApplication);
        }

        // POST: JobApplications/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("JobApplicationId,ApplicationDate,CoverLetter,ApplicationStatus,JobSeekerId,JobListingId")] JobApplication jobApplication)
        {
            if (id != jobApplication.JobApplicationId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(jobApplication);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!JobApplicationExists(jobApplication.JobApplicationId))
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
            ViewData["JobListingId"] = new SelectList(_context.JobListing, "Id", "Id", jobApplication.JobListingId);
            ViewData["JobSeekerId"] = new SelectList(_context.JobSeeker, "JobSeekerId", "JobSeekerId", jobApplication.JobSeekerId);
            return View(jobApplication);
        }

        // GET: JobApplications/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobApplication = await _context.JobApplication
                .Include(j => j.Listing)
                .Include(j => j.Seekers)
                .FirstOrDefaultAsync(m => m.JobApplicationId == id);
            if (jobApplication == null)
            {
                return NotFound();
            }

            return View(jobApplication);
        }

        // POST: JobApplications/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var jobApplication = await _context.JobApplication.FindAsync(id);
            if (jobApplication != null)
            {
                _context.JobApplication.Remove(jobApplication);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool JobApplicationExists(int id)
        {
            return _context.JobApplication.Any(e => e.JobApplicationId == id);
        }
    }
}
