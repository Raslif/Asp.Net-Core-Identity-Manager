using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
