using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager = null;
        private readonly SignInManager<IdentityUser> _signInManager = null;
        private readonly IEmailSender _emailSender = null;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
                                IEmailSender emailSender)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/");
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Error Occured in Input.");
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
                return LocalRedirect(returnUrl);

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Your account is Locked-out. Try after sometime...");
                return View(model);
            }

            ModelState.AddModelError(string.Empty, "Invalid Login attempt.");
            return View(model);
        }

        [HttpGet]
        public IActionResult Register() => View(new RegisterViewModel());

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Error Occured in Input.");
                return View(model);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email, Name = model.Name };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPassword() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Error Occured in Input.");
                return View(model);
            }

            var userDetails = await _userManager.FindByEmailAsync(model.Email);
            if (userDetails == null)
            {
                ModelState.AddModelError(string.Empty, "User not Found.");
                return View(model);
            }

            var tokenDetails = await _userManager.GeneratePasswordResetTokenAsync(userDetails);
            var callBackUrl = Url.Action(nameof(AccountController.ResetPassword), "Account", new { userId = userDetails.Id, code = tokenDetails }
                                                                                           , protocol: HttpContext.Request.Scheme);
            try
            {
                await _emailSender.SendEmailAsync(model.Email, "Reset Password - Identity Manager",
                                        "Please reset your password by clicking here: <a href=" + callBackUrl + ">link</a>");

                return RedirectToAction("PasswordResetMailSend");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Email Sending Failed.");
                return View(model);
            }
        }

        public IActionResult PasswordResetMailSend() => View();

        [HttpGet]
        public IActionResult ResetPassword(string userId, string code)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            {
                ViewData["Error"] = "The input is not valid.";
                return View("ResetPasswordError");
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Error Occured in Input.");
                return View(model);
            }

            var userDetails = await _userManager.FindByEmailAsync(model.Email);
            if (userDetails == null)
            {
                ModelState.AddModelError(string.Empty, "User not Found.");
                return View(model);
            }

            var result = await _userManager.ResetPasswordAsync(userDetails, model.Code, model.Password);
            if (result.Succeeded)
            {
                return View("ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
