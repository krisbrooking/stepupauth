using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace StepUpAuth.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            ViewData["Message"] = "This page is protected by username/password.";

            return View();
        }
        
        [Authorize(AuthenticationSchemes = Policies.SignUpInStepUp)]
        public IActionResult Secret()
        {
            ViewData["Message"] = "This page is protected by MFA.";

            return View();
        }

        public IActionResult Error(string message)
        {
            ViewBag.Message = message;
            return View();
        }
    }
}
