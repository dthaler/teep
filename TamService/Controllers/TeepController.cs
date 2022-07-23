// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
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
        public IActionResult Post()
        {
            if (!this.Request.Headers.ContainsKey("Accept"))
            {
                return new BadRequestResult();
            }
            string acceptMediaType = this.Request.Headers["Accept"].FirstOrDefault();

            if (this.Request.ContentLength == 0)
            {
                var session = new TamSession();
                string outboundMediaType;
                byte[] outboundMessage;
                if (session.ProcessConnect(acceptMediaType, out outboundMessage, out outboundMediaType) != 0)
                {
                    return new BadRequestResult();
                }

#if false
                var result = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(outboundMessage)
                };
                result.Content.Headers.ContentType = new MediaTypeHeaderValue(outboundMediaType);
#endif
                // See https://stackoverflow.com/questions/51641641/convert-from-httpresponsemessage-to-iactionresult-in-net-core
                return File(outboundMessage, outboundMediaType);
                
                //return ResponseMessage(result);

#if false
                var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
                response.Content = new ByteArrayContent(outboundMessage);
                response.Content.Headers.Add("Content-Type", outboundMediaType);
                return response;
#endif
            } else
            {
                return Ok();
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
