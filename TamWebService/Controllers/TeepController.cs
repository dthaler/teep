using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace TamWebService
{
    [Route("api/[controller]")]
    [ApiController]
    public class TeepController : ControllerBase
    {
        // GET: api/<TeepController>
        [HttpGet]
        public string Get()
        {
            return "Welcome to the TEEP GET content";
        }

#if true
        // POST api/<TeepController>
        [HttpPost]
        public IActionResult Post()
        {
            return Content("Hello", "text/vnd.familysearch.gedcom");
        }
#else
        // POST api/<TeepController>
        [HttpPost]
        public IActionResult Post([FromBody] byte[] value)
        {
            return Content("Hello", "text/vnd.familysearch.gedcom");
        }
#endif
    }
}
