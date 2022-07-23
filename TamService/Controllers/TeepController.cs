using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using TamCsOverCppShim;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace TamService
{
    [Route("api/[controller]")]
    [ApiController]
    public class TeepController : ControllerBase
    {
        // GET: api/<TeepController>
        [HttpGet]
        public string Get()
        {
            return "This is the RESTful endpoint for TEEP. Use POST with TEEP messages.";
        }

        // POST api/<TeepController>
        [HttpPost]
        public HttpResponseMessage Post()
        {
            if (!this.Request.Headers.ContainsKey("Accept"))
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.BadRequest);
            }
            string acceptMediaType = this.Request.Headers["Accept"].FirstOrDefault();

            if (this.Request.ContentLength == 0)
            {
                var session = new TamSession();
                int x = session.ProcessConnect(acceptMediaType);
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
            } else
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
            }
        }

#if false
        // POST api/<TeepController>
        [HttpPost]
        public HttpResponseMessage Post([FromBody] byte[] incomingData)
        {
            // log it or whatever

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        }
#endif
    }
}
