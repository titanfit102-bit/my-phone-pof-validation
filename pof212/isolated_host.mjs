import http from 'node:http';
import {createHash} from 'node:crypto';
import {lstat,readdir,readFile} from 'node:fs/promises';
import path from 'node:path';
const formats={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.woff2':'font/woff2'};
const digest=b=>createHash('sha256').update(b).digest('hex');
export async function inventory(directory){
  const files=new Map();let total=0;
  async function scan(dir,prefix=''){
    for(const entry of await readdir(dir,{withFileTypes:true})){
      const name=prefix?prefix+'/'+entry.name:entry.name;
      if(name.length>240||name.split('/').some(s=>!s||s==='..'||s==='.'||s.startsWith('.'))||!/^[A-Za-z0-9._/-]+$/.test(name))throw Error('unsafe artifact path');
      if(entry.isSymbolicLink())throw Error('symlink');
      if(entry.isDirectory()){await scan(path.join(dir,entry.name),name);continue}
      if(!entry.isFile()||!formats[path.extname(name)])throw Error('unsupported asset type');
      const filename=path.join(dir,entry.name),s=await lstat(filename);
      if(s.size>8*1024*1024||total+s.size>16*1024*1024||files.size>=64)throw Error('asset budget');
      const bytes=await readFile(filename);total+=bytes.length;
      files.set('/'+name,{filename,size:bytes.length,sha256:digest(bytes),type:formats[path.extname(name)]});
    }
  }
  await scan(path.resolve(directory));
  if(!files.has('/index.html')||![...files.keys()].some(n=>n.endsWith('.js')))throw Error('not a static built artifact');
  return {files,total};
}
export async function artifactServer({inventory,ip,studioOrigin}){
  if(!['127.0.0.2','127.0.0.3'].includes(ip)||!/^http:\/\/127\.0\.0\.1:\d+$/.test(studioOrigin))throw Error('loopback-only prototype');
  let active=true,count=0,origin='';const events=[],until=Date.now()+600000;
  const server=http.createServer(async(req,res)=>{
    const raw=(req.url||'/').split('?')[0],method=req.method;
    function reply(status,data='',type='text/plain; charset=utf-8'){
      res.writeHead(status,{'Content-Type':type,'X-Content-Type-Options':'nosniff','Cache-Control':'no-store',
        'Access-Control-Allow-Origin':'*','Cross-Origin-Resource-Policy':'cross-origin','Referrer-Policy':'no-referrer',
        'Content-Security-Policy':"default-src 'none'; script-src "+origin+"; style-src "+origin+" 'unsafe-inline'; img-src "+origin+" data:; font-src "+origin+" data:; connect-src 'none'; worker-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors "+studioOrigin});
      res.end(method==='HEAD'?'':data);events.push({path:raw,status});
    }
    if(!active||Date.now()>until){reply(410,'expired');return}
    if(++count>200){reply(429,'rate limited');return}
    if(!['GET','HEAD'].includes(method)){reply(405,'method');return}
    if(/%|\\|\/\.|\/\/|\.\./.test(raw)||!/^\/[A-Za-z0-9._/-]*$/.test(raw)){reply(400,'unsafe path');return}
    const file=inventory.files.get(raw==='/'?'/index.html':raw);
    if(!file){reply(404,'not in manifest');return}
    try{
      const s=await lstat(file.filename);const bytes=await readFile(file.filename);
      if(!s.isFile()||s.isSymbolicLink()||s.size!==file.size||digest(bytes)!==file.sha256)throw Error('integrity');
      reply(200,bytes,file.type);
    }catch{reply(409,'integrity mismatch')}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,ip,resolve)});
  origin='http://'+ip+':'+server.address().port;
  return {origin,events,revoke:()=>{active=false},close:()=>new Promise(resolve=>server.close(resolve))};
}
export async function studioHost(origins){
  const server=http.createServer((req,res)=>{
    if(req.url!=='/'&&req.url!=='/index.html'){res.writeHead(404).end();return}
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','X-Content-Type-Options':'nosniff',
      'Content-Security-Policy':"default-src 'none'; script-src 'none'; connect-src 'none'; frame-src "+origins.join(' ')+"; base-uri 'none'; form-action 'none'"});
    res.end('<!doctype html><title>Trusted Parent</title><div id="host-secret">PRIVATE_PARENT_VALUE</div>');
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
  return {origin:'http://127.0.0.1:'+server.address().port,close:()=>new Promise(resolve=>server.close(resolve))};
}
