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
using System.Security.Claims;

namespace ASM.Controllers
{
    public class JobSeekersController : Controller
    {
        private readonly ApplicationDbContext _context;

        public JobSeekersController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: JobSeekers
        public async Task<IActionResult> Index()
        {
            return View(await _context.JobSeeker.ToListAsync());
        }

        // GET: JobSeekers/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobSeeker = await _context.JobSeeker
                .FirstOrDefaultAsync(m => m.JobSeekerId == id);
            if (jobSeeker == null)
            {
                return NotFound();
            }

            return View(jobSeeker);
        }

        [Authorize(Roles = "ADMIN")]
        // GET: JobSeekers/Create
        public IActionResult Create()
        {
            return View();
        }

        [Authorize(Roles = "ADMIN")]
        // POST: JobSeekers/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("JobSeekerId,Fullname,Email")] JobSeeker jobSeeker)
        {
            if (ModelState.IsValid)
            {
                _context.Add(jobSeeker);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(jobSeeker);
        }

        //[Authorize()]
        //// GET: JobSeekers/Edit/5
        //public async Task<IActionResult> Edit(int? id)
        //{
        //    if (id == null)
        //    {
        //        return NotFound();
        //    }

        //    var jobSeeker = await _context.JobSeeker.FindAsync(id);
        //    if (jobSeeker == null)
        //    {
        //        return NotFound();
        //    }

        //    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        //    if (jobSeeker.UserId != userId)
        //    {
        //        return Forbid(); // or return Unauthorized(); depending on your requirements
        //    }
        //    return View(jobSeeker);
        //}

        [Authorize()]
        public async Task<IActionResult> Edit()
        {

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var jobSeeker = await _context.JobSeeker.Where(x=>x.UserId== userId).FirstOrDefaultAsync();
            if (jobSeeker == null)
            {
                return NotFound();
            }

            return View(jobSeeker);
        }

        [Authorize()]
        // POST: JobSeekers/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit([Bind("JobSeekerId,Fullname,Email,UserId")] JobSeeker jobSeeker)
        {
            //if (id != jobSeeker.JobSeekerId)
            //{
            //    return NotFound();
            //}

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            //jobSeeker = await _context.JobSeeker.Where(x => x.UserId == userId).FirstOrDefaultAsync();

            //if (jobSeeker.UserId != userId)
            //{
            //    return Forbid();
            //}

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(jobSeeker);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!JobSeekerExists(jobSeeker.JobSeekerId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                //return RedirectToAction(nameof(Index));
                return View(jobSeeker);
            }
            return View(jobSeeker);
        }

        [Authorize(Roles = "ADMIN")]
        // GET: JobSeekers/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var jobSeeker = await _context.JobSeeker
                .FirstOrDefaultAsync(m => m.JobSeekerId == id);
            if (jobSeeker == null)
            {
                return NotFound();
            }

            return View(jobSeeker);
        }

        [Authorize(Roles = "ADMIN")]
        // POST: JobSeekers/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var jobSeeker = await _context.JobSeeker.FindAsync(id);
            if (jobSeeker != null)
            {
                _context.JobSeeker.Remove(jobSeeker);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool JobSeekerExists(int id)
        {
            return _context.JobSeeker.Any(e => e.JobSeekerId == id);
        }
    }
}
