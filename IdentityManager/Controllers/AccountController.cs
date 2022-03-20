using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager = null;
        private readonly RoleManager<IdentityRole> _roleManager = null;
        private readonly SignInManager<IdentityUser> _signInManager = null;
        private readonly IEmailSender _emailSender = null;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
                                 IEmailSender emailSender, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
        }

        public IActionResult Index() => View();

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/Home/Index");
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Error Occured in Input.");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || (user != null && !await _userManager.CheckPasswordAsync(user, model.Password)))
            {
                ModelState.AddModelError(string.Empty, "You are not available in the system. Please register.");
                return View(model);
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                ModelState.AddModelError(string.Empty, "Please confirm the Email.");
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
        [AllowAnonymous]
        public async Task<IActionResult> Register()
        {
            if (!await _roleManager.RoleExistsAsync("Admin"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }

            return View(new RegisterViewModel { RoleList = GetListOfRoles() });
        }

        [HttpPost]
        [AllowAnonymous]
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
                string role = (!string.IsNullOrWhiteSpace(model.SelectedRole) && model.SelectedRole.ToLower() == "admin")
                                        ? model.SelectedRole : "User";
                await _userManager.AddToRoleAsync(user, role);

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callBackUrl = Url.Action(nameof(AccountController.ConfirmEmail), "Account", new { userId = user.Id, code = token }
                                             , protocol: HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Confirm Email - Identity Manager",
                                        "Please verify your email by clicking here: <a href=" + callBackUrl + ">link</a>");

                return View("RegistrationConfirmation");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            model.RoleList = GetListOfRoles();
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
                return View("Error");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return View("Error");

            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword() => View();

        [HttpPost]
        [AllowAnonymous]
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

        [HttpGet]
        [AllowAnonymous]
        public IActionResult PasswordResetMailSend() => View();

        [HttpGet]
        [AllowAnonymous]
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
        [AllowAnonymous]
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

        private List<SelectListItem> GetListOfRoles()
        {
            var listOfRoles = _roleManager.Roles.ToList();
            var roleSelectList = new List<SelectListItem>();

            if (listOfRoles.Count > 0)
            {
                var roles = listOfRoles.Select(x => x.Name).ToList();
                foreach (var item in roles)
                {
                    roleSelectList.Add(new SelectListItem
                    {
                        Value = item,
                        Text = item
                    });
                }
            }

            return roleSelectList;
        }
    }
}
