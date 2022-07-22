using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

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
        public void Post()
        {
        }

        // POST api/<TeepController>
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }
    }
}
