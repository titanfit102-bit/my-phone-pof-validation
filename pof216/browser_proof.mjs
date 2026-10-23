// PoF2.16: HTTPS/CHIPS+ESM feasibility probe; synthetic only, not production authentication.
import https from "node:https";
import fs from "node:fs/promises";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createRequire} from "node:module";
import {trustedParent,cookieArtifactHost} from "./cookie_host.mjs";
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const {chromium}=createRequire(path.join(root,"fixtures/vite/package.json"))("@playwright/test");
const tls={key:await fs.readFile(path.join(root,"pof216-ephemeral-key.pem")),cert:await fs.readFile(path.join(root,"pof216-ephemeral-cert.pem"))};
const checks=[],findings=[],servers=[],contexts=[];let browser,result;
function note(name,status,detail=""){checks.push({name,status,detail});console.log(status,name,detail)}
function requireFixture(name,ok){note(name,ok?"PASS":"FAIL");if(!ok)throw Error("Test fixture failed: "+name)}
function request(url){
 const u=new URL(url);return new Promise((resolve,reject)=>{
  const q=https.request({hostname:u.hostname,port:u.port,path:u.pathname,method:"GET",rejectUnauthorized:false},r=>{
   const chunks=[];r.on("data",b=>chunks.push(b));r.on("end",()=>resolve({status:r.statusCode,bytes:Buffer.concat(chunks).length}));
  });q.on("error",reject);q.end();
 });
}
async function append(page,url,title){
 await page.evaluate(({url,title})=>{const f=document.createElement("iframe");f.title=title;f.setAttribute("sandbox","allow-scripts");f.referrerPolicy="no-referrer";f.src=url;document.body.append(f)},{url,title});
 return page.frameLocator('iframe[title="'+title+'"]');
}
try{
 const origins=[],parent=await trustedParent(tls,origins);servers.push(parent);
 const A=await cookieArtifactHost({tls,dist:path.join(root,"fixtures/vite/dist"),tenant:"A",ip:"127.0.0.2",studioOrigin:parent.origin,scriptMode:"credentialed"});
 const B=await cookieArtifactHost({tls,dist:path.join(root,"fixtures/vite/dist"),tenant:"B",ip:"127.0.0.3",studioOrigin:parent.origin,scriptMode:"anonymous"});
 servers.push(A,B);origins.push(A.origin,B.origin);
 requireFixture("Three distinct HTTPS loopback origins",new Set([parent.origin,A.origin,B.origin]).size===3);
 requireFixture("Copied URL denied without browser authentication",(await request(A.url)).status===401);
 requireFixture("Other tenant URL denied without browser authentication",(await request(B.url)).status===401);
 browser=await chromium.launch({headless:true});
 const owner=await browser.newContext({ignoreHTTPSErrors:true});contexts.push(owner);
 let cookiesInstalled=false,reason="";
 try{const {url,...c}=A.mockCookie();await owner.addCookies([{...c,domain:new URL(url).hostname,partitionKey:"https://127.0.0.1"}]);cookiesInstalled=(await owner.cookies(A.url)).some(c=>c.name===A.cookieName)}
 catch(e){reason=String(e.message||e).slice(0,240)}
 note("Partitioned HttpOnly Secure cookie accepted",cookiesInstalled?"PASS":"FAIL",reason);
 const p=await owner.newPage();await p.goto(parent.origin);
 const frame=await append(p,A.url,"authorized");
 let rendered=false;
 try{await frame.locator("#pof-header").waitFor({timeout:9500});rendered=true}catch(e){reason=String(e.message||e).slice(0,200)}
 const entry=A.events.find(e=>e.path==="/index.html");
 note("Secure cookie accompanies sandboxed iframe document",entry?.authenticated?"PASS":"FAIL",JSON.stringify({status:entry?.status,cookiePresent:entry?.cookiePresent}));
 note("Credentialed ESM entry renders",rendered?"PASS":"FAIL",rendered?"Official Vite entry mounted":reason);
 let chunk=false,png=false,opaque=false;
 if(rendered){
  try{await frame.locator("#pof-load").click();await frame.locator("#pof-status").getByText(/CHUNK READY/).waitFor({timeout:9000});
   chunk=A.events.some(e=>/\/assets\/lazy-.*\.js$/.test(e.path)&&e.status===200&&e.authenticated);
  }catch(e){reason=String(e.message||e).slice(0,240)}
  note("Dynamic import ESM chunk with cookie",chunk?"PASS":"FAIL",reason);
  try{png=await frame.locator("#pof-img").evaluate(async img=>{await img.decode();return img.naturalWidth===2})}catch{}
  note("PNG asset decoded",png?"PASS":"FAIL");
  const isolation=await frame.locator("body").evaluate(()=>{
   let parentDenied=false,storageDenied=false;
   try{void parent.document.querySelector("#host-secret")}catch{parentDenied=true}
   try{void localStorage.getItem("x")}catch{storageDenied=true}
   return {opaque:origin==="null",parentDenied,storageDenied};
  });
  opaque=isolation.opaque&&isolation.parentDenied&&isolation.storageDenied;
  note("Opaque origin still blocks parent and storage",opaque?"PASS":"FAIL");
 }else note("Dynamic import and PNG", "NOT_RUN","entrypoint did not render");
 const fresh=await browser.newContext({ignoreHTTPSErrors:true});contexts.push(fresh);
 const tab=await fresh.newPage();const copied=await tab.goto(A.url,{waitUntil:"domcontentloaded"});
 requireFixture("Stolen URL blocked in cookie-free Chromium context",copied?.status()===401);
 await p.goto(parent.origin+"/attack");
 await p.evaluate(()=>{const f=document.createElement("iframe");f.title="untrusted-opaque";f.setAttribute("sandbox","allow-scripts");f.srcdoc="<!doctype html><body>UNTRUSTED</body>";document.body.append(f)});
 const evil=p.frameLocator('iframe[title="untrusted-opaque"]');
 await evil.locator("body").waitFor();
 const entryJs=A.events.find(e=>/\/assets\/index-.*\.js$/.test(e.path))?.path||"/assets/not-found.js";
 let sibling={readable:false,status:0};
 try{
  sibling=await evil.locator("body").evaluate(async url=>{
   try{const r=await fetch(url,{credentials:"include",cache:"no-store"});const t=await r.text();
    return {readable:r.ok&&t.length>100,status:r.status,bytes:t.length}}
   catch(e){return {readable:false,status:0,error:String(e).slice(0,140)}}
  },A.origin+entryJs);
 }catch(e){sibling={readable:false,status:0,error:String(e).slice(0,140)}}
 note("Untrusted opaque sibling frame reads A's script",sibling.readable?"CRITICAL_LEAK":"BLOCKED_OR_UNPROVEN",JSON.stringify(sibling));
 if(sibling.readable)findings.push("CRITICAL: opaque sibling with same browser cookie can read authenticated JS via ACAO:null and ACAC:true");
 else findings.push("Sibling read was not demonstrated; absence of exploit in this configuration is NOT security proof");
 const other=await browser.newContext({ignoreHTTPSErrors:true});contexts.push(other);
 let otherCookie=false;try{const {url,...c}=B.mockCookie();await other.addCookies([{...c,domain:new URL(url).hostname,partitionKey:"https://127.0.0.1"}]);otherCookie=true}catch{}
 const pB=await other.newPage();await pB.goto(parent.origin);const fB=await append(pB,B.url,"anonymous-modules");
 let anonymousRender=false;try{await fB.locator("#pof-header").waitFor({timeout:4000});anonymousRender=true}catch{}
 note("Anonymous crossorigin entry does not render when module requires cookies",!anonymousRender?"PASS_EXPECTED_DENIAL":"UNEXPECTED_RENDER",JSON.stringify({otherCookie,anonymousRender}));
 A.revoke();requireFixture("Revocation denies new reads",(await request(A.url)).status===410);
 const off=await browser.newPage();await off.goto("about:blank");
 await off.evaluate(()=>{const f=document.createElement("iframe");f.title="local-blob";f.setAttribute("sandbox","allow-scripts");f.srcdoc="<!doctype html><body>LOCAL</body>";document.body.append(f)});
 let localModule=false;
 try{localModule=await off.frameLocator('iframe[title="local-blob"]').locator("body").evaluate(async()=>{
  const url=URL.createObjectURL(new Blob(['export const x="BLOB_OK"'],{type:"text/javascript"}));
  try{const module=await import(url);return module.x==="BLOB_OK"}finally{URL.revokeObjectURL(url)}
 })}catch(e){reason=String(e.message||e).slice(0,160)}
 note("Minimal in-memory blob dynamic import in opaque iframe",localModule?"PASS":"FAIL",reason);
 await off.close();
 result={status:"EXPERIMENT_COMPLETED_PRIVATE_NO_GO",checks,findings,
  results:{cookieInstalled:cookiesInstalled,htmlCookieSeen:Boolean(entry?.authenticated),credentialedEsmRendered:rendered,dynamicChunkCookieAuth:chunk,imageDecoded:png,opaqueIsolation:opaque,
   copiedUrlDeniedInFreshBrowser:copied?.status()===401,untrustedOpaqueSiblingRead:sibling.readable,anonymousModulesRendered:anonymousRender,localBlobEsm:localModule},
  releaseGates:{production:"NO_GO",crossOpaqueOriginConfidentiality:"NOT_PROVEN",identityBoundPerAsset:"NOT_PROVEN",realLogin:"NOT_IMPLEMENTED",multibrowser:"NOT_RUN"},
  warnings:["Cookies injected by Playwright; no real login or server-side identity provider was implemented.",
   "Self-signed ephemeral HTTPS fixture: not a production TLS security verification.",
   "Minimal blob-module is not a Vite multi-chunk local import proof."],
  requestEvents:{A:A.events,B:B.events}};
}catch(e){result={status:"INFRA_OR_TEST_FAILURE",error:String(e.stack||e),checks,findings};console.error(e.stack||e);process.exitCode=1}
finally{
 await browser?.close().catch(()=>{});
 for(const server of servers.reverse())await server.close().catch(()=>{});
 await fs.mkdir(path.join(root,"results"),{recursive:true});
 await fs.writeFile(path.join(root,"results/pof216-experiment.json"),JSON.stringify(result,null,2));
}
