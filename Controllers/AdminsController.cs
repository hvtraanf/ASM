using ASM.Data;
using ASM.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using System.Security.Claims;

namespace ASM.Controllers
{
    [Authorize(Roles ="ADMIN")]
    public class AdminsController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IUserStore<IdentityUser> _userStore;
        private readonly IUserEmailStore<IdentityUser> _emailStore;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AdminsController> _logger;

        public AdminsController(
            UserManager<IdentityUser> userManager,
            IUserStore<IdentityUser> userStore,
            SignInManager<IdentityUser> signInManager,
            ILogger<AdminsController> logger,
            ApplicationDbContext context)
        {
            _userManager = userManager;
            _userStore = userStore;
            _signInManager = signInManager;
            _logger = logger;
            _context = context;
            _emailStore = GetEmailStore();
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Employers()
        {
           
            return View(await _context.Employer.Include(x => x.User).ToListAsync());
        }

        public async Task<IActionResult> JobSeekers()
        {

            return View(await _context.JobSeeker.ToListAsync());
        }

        public async Task<IActionResult> DetailsEmployers(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var employer = await _context.Employer
                .Include(x => x.User)
                .FirstOrDefaultAsync(m => m.EmployerId == id);
            if (employer == null)
            {
                return NotFound();
            }

            return View(employer);
        }

        public async Task<IActionResult> DetailsJobSeeker(int id)
        {
            var jobSeeker = await _context.JobSeeker
                .Include(x => x.User)
                .FirstOrDefaultAsync(m => m.JobSeekerId == id);
            if (jobSeeker == null)
            {
                return NotFound();
            }

            return View(jobSeeker);
        }

        //Employers related
        // GET: Employers/Create
        public IActionResult CreateEmployers()
        {
            return View();
        }

        // POST: Employers/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateEmployers([Bind("EmployerId,CompanyName,ContactEmail")] Employer employer)
        {
            if (ModelState.IsValid)
            {
                _context.Add(employer);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(employer);
        }

        public IActionResult RegisterUser() { 
            return View(); 
        }

        [HttpPost]
        public async Task<IActionResult> RegisterUser(RegisterVM registerVM)
        {
            if (ModelState.IsValid)
            {
                var user = CreateUser();

                await _userStore.SetUserNameAsync(user, registerVM.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, registerVM.Email, CancellationToken.None);

                var result = await _userManager.CreateAsync(user, registerVM.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    await _userManager.AddToRoleAsync(user, registerVM.Role);

                    if (registerVM.Role == "EMPLOYER")
                    {
                        var employer = new Employer { CompanyName = registerVM.Name, EmployerId = Guid.NewGuid().ToString(), UserId = user.Id, ContactEmail = user.Email };
                        _context.Employer.Add(employer);
                    }
                    else if (registerVM.Role == "JOBSEEKER")
                    {
                        var jobSeeker = new JobSeeker { Fullname = registerVM.Name, UserId = user.Id, Email = user.Email };
                        _context.JobSeeker.Add(jobSeeker);
                    }
                    _context.SaveChanges();

                    var userId = await _userManager.GetUserIdAsync(user);

                    return RedirectToAction(nameof(Index));

                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }
            return View();
        }


        private IdentityUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<IdentityUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(IdentityUser)}'. " +
                    $"Ensure that '{nameof(IdentityUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }

        private IUserEmailStore<IdentityUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<IdentityUser>)_userStore;
        }

        // GET: Employers/Edit/5
        public async Task<IActionResult> EditEmployers(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var employer = await _context.Employer.FindAsync(id);
            if (employer == null)
            {
                return NotFound();
            }
            return View(employer);
        }

        // POST: Employers/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditEmployers(string id, [Bind("EmployerId,CompanyName,ContactEmail")] Employer employer)
        {
            if (id != employer.EmployerId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(employer);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!EmployerExists(employer.EmployerId))
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
            return View(employer);
        }

        // GET: Employers/Delete/5
        public async Task<IActionResult> DeleteEmployers(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var employer = await _context.Employer
                .FirstOrDefaultAsync(m => m.EmployerId == id);
            if (employer == null)
            {
                return NotFound();
            }

            return View(employer);
        }

        // POST: Employers/Delete/5
        [HttpPost, ActionName("DeleteEmployers")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmedEmployers(string id)
        {
            var employer = await _context.Employer.FindAsync(id);
            if (employer != null)
            {
                _context.Employer.Remove(employer);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }


        public async Task<IActionResult> DeleteJobSeeker(int id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var employer = await _context.JobSeeker
                .FirstOrDefaultAsync(m => m.JobSeekerId == id);
            if (employer == null)
            {
                return NotFound();
            }

            return View(employer);
        }

        // POST: Employers/Delete/5
        [HttpPost, ActionName("DeleteEmployers")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmedJobSeeker(string id)
        {
            var jobSeeker = await _context.JobSeeker.FindAsync(id);
            if (jobSeeker != null)
            {
                _context.JobSeeker.Remove(jobSeeker);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool EmployerExists(string id)
        {
            return _context.Employer.Any(e => e.EmployerId == id);
        }

        public async Task<IActionResult> JobListings()
        {

            return View(await _context.JobListing.ToListAsync());
        }

        public async Task<IActionResult> EditJobListing(int? id)
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

        // POST: JobListings/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditJobListing(int id, [Bind("Id,JobTitle,JobDescription,JobRequirement,JobType,EmployerId,ApplicationDeadline,Approved")] JobListing jobListing)
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

        private bool JobListingExists(int id)
        {
            return _context.JobListing.Any(e => e.Id == id);
        }


        public async Task<IActionResult> EditJobSeeker(int id)
        {

            var jobSeeker = await _context.JobSeeker.Where(x => x.JobSeekerId == id).FirstOrDefaultAsync();
            if (jobSeeker == null)
            {
                return NotFound();
            }

            
            return View(jobSeeker);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditJobSeeker(int id, [Bind("JobSeekerId,Fullname,Email,UserId")] JobSeeker jobSeeker)
        {

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

        private bool JobSeekerExists(int id)
        {
            return _context.JobSeeker.Any(e => e.JobSeekerId == id);
        }

    }
}
