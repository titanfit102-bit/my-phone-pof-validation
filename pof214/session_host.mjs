// PoF2.14 — disposable bearer-capability experiment only.
// IMPORTANT: A stolen URL grants access; this is NOT identity-bound authorization.
import http from 'node:http';
import path from 'node:path';
import {readFile} from 'node:fs/promises';
import {randomBytes,createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {inventory} from '../pof212/isolated_host.mjs';

const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.woff2':'font/woff2'};
const safe=(a,b)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y)};
const key=randomBytes(32); // never checked into GitHub
export async function makeFixtureSession({tenant,owner,ip,studioOrigin,dist}){
  if(!['127.0.0.2','127.0.0.3'].includes(ip)||!/^http:\/\/127\.0\.0\.1:\d+$/.test(studioOrigin))throw Error('loopback-only experiment');
  const input=await inventory(dist);
  const id=randomBytes(12).toString('hex');
  const expiry=Date.now()+120000;
  const files=new Map();
  const fileDigest=createHash('sha256').update([...input.files.values()].map(f=>f.sha256).join(':')).digest('hex');
  const signing=id+'|'+tenant+'|'+fileDigest+'|'+expiry;
  const capability=createHmac('sha256',key).update(signing).digest('base64url');
  const prefix='/v/'+id+'/'+capability;
  for(const [name,entry] of input.files){
    let bytes=await readFile(entry.filename);
    if(name==='/index.html'){
      const html=bytes.toString('utf8').replaceAll('src="/assets/','src="'+prefix+'/assets/')
        .replaceAll('href="/assets/','href="'+prefix+'/assets/');
      if(html.includes('src="/assets/')||html.includes('href="/assets/'))throw Error('entrypoints not rewritten');
      bytes=Buffer.from(html);
    }
    if(/\/assets\/index-[^.]+\.js$/.test(name)){
      const original=bytes.toString('utf8');
      if(!original.includes('"/pixel.png"'))throw Error('expected PNG reference missing');
      bytes=Buffer.from(original.replaceAll('"/pixel.png"','"'+prefix+'/pixel.png"'));
    }
    files.set(name,{bytes,sha256:digest(bytes),mime:mime[path.extname(name)]});
  }
  let origin='',revoked=false,expired=false,used=0;
  const log=[];
  const server=http.createServer((req,res)=>{
    const raw=req.url||'';
    const match=/^\/v\/([0-9a-f]{24})\/([A-Za-z0-9_-]{43})(\/[A-Za-z0-9._/-]*)$/.exec(raw);
    function finish(status,message=''){
      res.writeHead(status,{'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'});
      res.end(message);log.push({path:match?.[3]||'REDACTED',status}); // capability never logged
    }
    if(!match||match[1]!==id||!safe(match[2],capability)){finish(404);return}
    if(revoked||expired||Date.now()>=expiry){finish(410);return}
    if(++used>150){finish(429);return}
    if(!['GET','HEAD'].includes(req.method)){finish(405);return}
    if(req.headers.range){finish(416);return}
    const requested=match[3]==='/'?'/index.html':match[3];
    if(requested.includes('//')||requested.includes('..')||requested.includes('/.')||requested.includes('\\')){finish(404);return}
    const item=files.get(requested);
    if(!item){finish(404);return}
    if(digest(item.bytes)!==item.sha256){finish(409);return}
    const csp="default-src 'none'; script-src "+origin+"; style-src "+origin+" 'unsafe-inline'; img-src "+origin+" data:; font-src "+origin+" data:; connect-src 'none'; worker-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors "+studioOrigin;
    res.writeHead(200,{
      'Content-Type':item.mime,'Cache-Control':'no-store, max-age=0','X-Content-Type-Options':'nosniff',
      'Access-Control-Allow-Origin':'*','Cross-Origin-Resource-Policy':'cross-origin',
      'Referrer-Policy':'no-referrer','Content-Security-Policy':csp
    });
    res.end(req.method==='HEAD'?'':item.bytes);log.push({path:requested,status:200});
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,ip,resolve)});
  origin='http://'+ip+':'+server.address().port;
  const url=origin+prefix+'/';
  return {
    tenant,owner,id,url,origin,prefix,log,manifestDigest:fileDigest,
    grant:subject=>{if(subject!==owner)throw Error('DENIED');return url},
    revoke:()=>{revoked=true},expire:()=>{expired=true},
    tamper:name=>{const f=files.get(name);if(!f)throw Error('missing');f.bytes=Buffer.concat([f.bytes,Buffer.from('tamper')])},
    close:()=>new Promise(resolve=>server.close(resolve))
  };
}
export async function makeTrustedHost(getOrigins){
  const server=http.createServer((req,res)=>{
    if(req.url!=='/'){res.writeHead(404).end();return}
    const origins=getOrigins();
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8',
      'Content-Security-Policy':"default-src 'none'; frame-src "+origins.join(' ')+"; script-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'"});
    res.end('<!doctype html><title>Trusted control plane fixture</title><p id="secret">PARENT_ONLY</p>');
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
  return {origin:'http://127.0.0.1:'+server.address().port,close:()=>new Promise(resolve=>server.close(resolve))};
}
