using Microsoft.AspNetCore.Identity.UI.Services;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System;
using Mailjet.Client;
using Mailjet.Client.Resources;
using Newtonsoft.Json.Linq;

namespace IdentityManager.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration = null;
        private MailJetOptions _mailJetOptions = null;
        public MailJetEmailSender(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _mailJetOptions = _configuration.GetSection("MailJet").Get<MailJetOptions>();
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            MailjetClient client = new(_mailJetOptions.ApiKey, _mailJetOptions.SecretKey);
            MailjetRequest request = new MailjetRequest
            {
                Resource = SendV31.Resource
            }.Property(Send.Messages, new JArray {
             new JObject {
              {
               "From", new JObject {
                    {"Email", "your-email"},
                    {"Name", "Rasu"}
               }}, 
                 {
                   "To", new JArray {
                        new JObject {
                        { "Email", email },
                        { "Name", "Raslif" }
                      }
                }}, 
                 { "Subject", subject }, 
                 { "HTMLPart", htmlMessage }
               }
             });
            
            MailjetResponse response = await client.PostAsync(request);
            //if (response.IsSuccessStatusCode)
            //{
            //    Console.WriteLine(string.Format("Total: {0}, Count: {1}\n", response.GetTotal(), response.GetCount()));
            //    Console.WriteLine(response.GetData());
            //}
            //else
            //{
            //    Console.WriteLine(string.Format("StatusCode: {0}\n", response.StatusCode));
            //    Console.WriteLine(string.Format("ErrorInfo: {0}\n", response.GetErrorInfo()));
            //    Console.WriteLine(response.GetData());
            //    Console.WriteLine(string.Format("ErrorMessage: {0}\n", response.GetErrorMessage()));
            //}
        }
    }
}
