// PoF2.16: HTTPS loopback partitioned cookie / opaque ESM feasibility study.
// SYNTHETIC ONLY. Deliberate ACAO:null + ACAC:true probes a cross-opaque-origin risk.
// Never deploy as a real private artifact host.
import https from "node:https";
import {readFile} from "node:fs/promises";
import {randomBytes,createHash,timingSafeEqual} from "node:crypto";
import {inventory} from "../pof212/isolated_host.mjs";
const hash=b=>createHash("sha256").update(b).digest("hex");
const mime={".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8",".png":"image/png",".woff2":"font/woff2"};
const constEq=(a,b)=>{const x=Buffer.from(a||""),y=Buffer.from(b||"");return x.length===y.length && timingSafeEqual(x,y)};
function reply(res,status,headers={},bytes=""){res.writeHead(status,headers);res.end(bytes)}
export async function trustedParent(tls,origins){
 const server=https.createServer(tls,(req,res)=>{
  if(req.url!=="/"&&req.url!=="/attack"){reply(res,404);return}
  const attack=req.url==="/attack";
  reply(res,200,{"Content-Type":"text/html; charset=utf-8",
    "Content-Security-Policy":"default-src 'none'; script-src 'unsafe-inline'; frame-src "+origins.join(" ")+" 'self'; connect-src "+(attack?origins.join(" "):"'none'")+"; object-src 'none'; base-uri 'none'",
    "Cache-Control":"no-store"},'<!doctype html><title>PoF trusted host</title><div id="host-secret">HOST_PRIVATE</div>');
 });
 await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve)});
 return {origin:"https://127.0.0.1:"+server.address().port,close:()=>new Promise(r=>server.close(r))};
}
export async function cookieArtifactHost({tls,dist,ip,tenant,studioOrigin,scriptMode}){
 if(!["127.0.0.2","127.0.0.3"].includes(ip)||!/^https:\/\/127\.0\.0\.1:\d+$/.test(studioOrigin)||!["credentialed","anonymous"].includes(scriptMode))throw Error("invalid loopback fixture");
 const entries=(await inventory(dist)).files,assets=new Map(),events=[];
 for(const [url,f] of entries){
  let bytes=await readFile(f.filename);
  if(url==="/index.html"){
   const html=bytes.toString("utf8");
   if(!/type="module" crossorigin/.test(html))throw Error("Vite fixture script not found");
   bytes=Buffer.from(scriptMode==="credentialed"?
     html.replace('type="module" crossorigin','type="module" crossorigin="use-credentials"'):html);
  }
  const type=mime[url.slice(url.lastIndexOf("."))]||"application/octet-stream";
  assets.set(url,{bytes,digest:hash(bytes),type});
 }
 const cookieName="pof_"+tenant,secret=randomBytes(24).toString("hex");
 let revoked=false,origin="";
 const server=https.createServer(tls,(req,res)=>{
  const raw=req.url||"/";
  const pathname=raw==="/"?"/index.html":raw;
  const cookie=(req.headers.cookie||"").split(";").map(s=>s.trim()).find(x=>x.startsWith(cookieName+"="))?.slice(cookieName.length+1)||"";
  const cookiePresent=Boolean(cookie),authenticated=constEq(cookie,secret);
  let status=200;
  if(revoked)status=410;
  else if(!["GET","HEAD"].includes(req.method))status=405;
  else if(raw.includes("?")||raw.includes("%")||raw.includes("..")||raw.includes("//")||!/^\/[A-Za-z0-9._/-]*$/.test(raw))status=404;
  else if(!authenticated)status=401;
  else if(!assets.has(pathname))status=404;
  else if(req.headers.range)status=416;
  else if(hash(assets.get(pathname).bytes)!==assets.get(pathname).digest)status=409;
  const base={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","Cross-Origin-Resource-Policy":"cross-origin",
     // Deliberately dangerous for authenticated resources when any opaque document can send cookies.
     "Access-Control-Allow-Origin":"null","Access-Control-Allow-Credentials":"true","Vary":"Origin, Cookie"};
  if(status===200){
   const a=assets.get(pathname);
   base["Content-Type"]=a.type;
   base["Content-Security-Policy"]="default-src 'none'; script-src "+origin+"; style-src "+origin+" 'unsafe-inline'; img-src "+origin+" data:; font-src "+origin+" data:; connect-src 'none'; worker-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors "+studioOrigin;
   reply(res,200,base,req.method==="HEAD"?"":a.bytes);
  }else reply(res,status,base);
  // Avoid recording Cookie, capability, body, query or full URL in any evidence.
  events.push({path:pathname,status,cookiePresent,authenticated,method:req.method,originHeader:req.headers.origin||null,fetchSite:req.headers["sec-fetch-site"]||null});
 });
 await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,ip,resolve)});
 origin="https://"+ip+":"+server.address().port;
 return {
  tenant,origin,url:origin+"/",cookieName,events,scriptMode,
  mockCookie:()=>({name:cookieName,value:secret,url:origin,path:"/",sameSite:"None",secure:true,httpOnly:true}),
  revoke:()=>{revoked=true},
  close:()=>new Promise(resolve=>server.close(resolve))
 };
}
