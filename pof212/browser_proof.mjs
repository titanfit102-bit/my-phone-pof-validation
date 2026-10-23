import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {request as httpRequest} from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import {inventory,artifactServer,studioHost} from './isolated_host.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const {chromium}=createRequire(path.join(root,'fixtures/vite/package.json'))('@playwright/test');
const steps=[],sessions=[];let browser,temporary;
function pass(label,truth,detail=''){if(!truth)throw Error(label+' '+detail);steps.push({label,result:'PASS',detail});console.log('PASS',label,detail)}
function httpGet(origin,raw,method='GET'){
  const u=new URL(origin);
  return new Promise((resolve,reject)=>{
    const r=httpRequest({hostname:u.hostname,port:u.port,path:raw,method},res=>{
      const body=[];res.on('data',b=>body.push(b));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,data:Buffer.concat(body)}));
    });r.on('error',reject);r.end();
  });
}
async function appendFrame(page,url,title){
  await page.evaluate(args=>{
    const f=document.createElement('iframe');f.title=args.title;f.setAttribute('sandbox','allow-scripts');
    f.setAttribute('referrerpolicy','no-referrer');f.src=args.url;f.width='400';f.height='430';document.body.append(f);
  },{url,title});
  return page.frameLocator('iframe[title="'+title+'"]');
}
let result;
try{
  const source=path.join(root,'fixtures/vite/dist');
  const files=await inventory(source);
  pass('bounded manifest of official Vite dist',files.files.size>=5,files.files.size+' immutable files');
  const origins=[],host=await studioHost(origins);sessions.push(host);
  const a=await artifactServer({inventory:files,ip:'127.0.0.2',studioOrigin:host.origin});sessions.push(a);origins.push(a.origin);
  const b=await artifactServer({inventory:files,ip:'127.0.0.3',studioOrigin:host.origin});sessions.push(b);origins.push(b.origin);
  pass('three different origin hosts / sites',new Set([new URL(host.origin).hostname,new URL(a.origin).hostname,new URL(b.origin).hostname]).size===3);
  const landing=await httpGet(a.origin,'/');
  const bundle=[...files.files.keys()].find(x=>/\/assets\/index-.*\.js$/.test(x));
  const entry=await httpGet(a.origin,bundle);
  const csp=landing.headers['content-security-policy'];
  pass('strict CSP and frame-ancestors header',landing.status===200&&csp.includes("default-src 'none'")&&csp.includes('frame-ancestors '+host.origin)&&csp.includes("connect-src 'none'"));
  pass('JavaScript MIME and credential-free CORS',entry.status===200&&entry.headers['content-type'].includes('text/javascript')&&entry.headers['access-control-allow-origin']==='*'&&!entry.headers['access-control-allow-credentials']);
  const malformed=await Promise.all([httpGet(a.origin,'/.env'),httpGet(a.origin,'/%2e%2e/key'),httpGet(a.origin,'/other.js'),httpGet(a.origin,'/','POST'),httpGet(a.origin,'/assets/../index.html')]);
  pass('path, method and manifest denials',malformed.map(x=>x.status).join(',')==='400,400,404,405,400',malformed.map(x=>x.status).join(','));
  browser=await chromium.launch({headless:true});
  const page=await browser.newPage(),errors=[],responses=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('response',r=>{if(/\.js(?:\?|$)/.test(r.url()))responses.push({url:r.url(),status:r.status()})});
  await page.goto(host.origin,{waitUntil:'domcontentloaded'});
  const frame=await appendFrame(page,a.origin+'/','PoF A');
  await frame.locator('#pof-header').waitFor({timeout:20000});
  pass('official Vite React renders in cross-site iframe',(await frame.locator('#pof-header').innerText()).includes('Vite React: READY'));
  pass('Vite CSS loaded',await frame.locator('body').evaluate(x=>getComputedStyle(x).backgroundColor==='rgb(248, 250, 252)'));
  const before=new Set(responses.map(x=>x.url));
  await frame.locator('#pof-load').click();
  await frame.locator('#pof-status').getByText(/CHUNK READY/).waitFor({timeout:15000});
  pass('dynamic import changes React state',true);
  pass('dynamic chunk HTTP 200 after click',responses.some(x=>x.status===200&&!before.has(x.url)&&/\/assets\/lazy-[^/]+\.js$/.test(x.url)));
  pass('local image decoded',await frame.locator('#pof-img').evaluate(async el=>{await el.decode();return el.naturalWidth===2&&el.naturalHeight===2}));
  const isolation=await frame.locator('body').evaluate(()=>{
    let deniedParent=false,deniedStorage=false;
    try{void parent.document.getElementById('host-secret')}catch{deniedParent=true}
    try{localStorage.getItem('token')}catch{deniedStorage=true}
    return {origin:window.origin,deniedParent,deniedStorage};
  });
  pass('opaque origin blocks parent DOM and storage',isolation.origin==='null'&&isolation.deniedParent&&isolation.deniedStorage);
  const countB=b.events.length;
  const denied=await frame.locator('body').evaluate(async u=>{try{await fetch(u+'/index.html');return false}catch{return true}},b.origin);
  pass('CSP blocks cross-session fetch',denied&&b.events.length===countB);
  const imageDenied=await frame.locator('body').evaluate(u=>new Promise(resolve=>{
    const img=new Image();img.onerror=()=>resolve(true);img.onload=()=>resolve(false);img.src=u+'/pixel.png';
    setTimeout(()=>resolve(false),1500);
  }),b.origin);
  pass('CSP blocks cross-session image egress',imageDenied&&b.events.length===countB);
  pass('sandbox blocks popup',await frame.locator('body').evaluate(()=>window.open('about:blank')===null));
  const other=await appendFrame(page,b.origin+'/','PoF B');
  await other.locator('#pof-header').waitFor({timeout:20000});
  pass('second independent session renders',(await other.locator('#pof-header').innerText()).includes('READY'));
  await frame.locator('body').evaluate(()=>location.reload());
  await frame.locator('#pof-header').waitFor({timeout:20000});
  pass('iframe reload retains official build',await frame.locator('#pof-status').innerText()==='waiting');
  await fs.mkdir(path.join(root,'results'),{recursive:true});
  await page.screenshot({path:path.join(root,'results/pof212-browser.png'),fullPage:true});
  const wrong=await studioHost(origins);sessions.push(wrong);
  const hostile=await browser.newPage();await hostile.goto(wrong.origin);
  const unauthorized=await appendFrame(hostile,a.origin+'/','wrong-parent');
  let rendered=false;
  try{await unauthorized.locator('#pof-header').waitFor({timeout:1200});rendered=true}catch{}
  pass('frame-ancestors denies unauthorized parent',!rendered);
  await hostile.close();
  temporary=await fs.mkdtemp(path.join(os.tmpdir(),'pof212-sha-'));
  await fs.cp(source,temporary,{recursive:true});
  const mutatedInventory=await inventory(temporary);
  const lazy=[...mutatedInventory.files.keys()].find(n=>/\/assets\/lazy-.*\.js$/.test(n));
  const file=mutatedInventory.files.get(lazy).filename;
  const original=await fs.readFile(file,'utf8');await fs.writeFile(file,original.replace('CHUNK','LUNCH'));
  const mutant=await artifactServer({inventory:mutatedInventory,ip:'127.0.0.3',studioOrigin:host.origin});sessions.push(mutant);
  pass('changed immutable bundle blocked with SHA-256', (await httpGet(mutant.origin,lazy)).status===409);
  a.revoke();
  pass('revoked preview is inaccessible',(await httpGet(a.origin,'/')).status===410);
  pass('other session remains independent',(await httpGet(b.origin,'/')).status===200);
  pass('no browser JavaScript errors',errors.length===0,errors.join(';'));
  await page.close();
  result={status:'PASS',count:steps.length,steps,origins:{studio:host.origin,A:a.origin,B:b.origin},sha256:[...files.files].map(([name,v])=>({name,sha256:v.sha256,bytes:v.size})),requests:{A:a.events,B:b.events}};
}catch(e){console.error(e.stack||e);result={status:'FAIL',count:steps.length,steps,error:String(e.stack||e)};process.exitCode=1}
finally{
  await browser?.close().catch(()=>{});
  for(const s of sessions.reverse())await s.close().catch(()=>{});
  if(temporary)await fs.rm(temporary,{recursive:true,force:true}).catch(()=>{});
  await fs.mkdir(path.join(root,'results'),{recursive:true});
  await fs.writeFile(path.join(root,'results/pof212-browser-proof.json'),JSON.stringify(result,null,2));
}
