// PoF2.14: exercise ESM with bearer capabilities, then PROVE copied-URL replay risk.
import path from 'node:path';
import fs from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import http from 'node:http';
import {createRequire} from 'node:module';
import {makeFixtureSession,makeTrustedHost} from './session_host.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const {chromium}=createRequire(path.join(root,'fixtures/vite/package.json'))('@playwright/test');
const dist=path.join(root,'fixtures/vite/dist');
const steps=[],all=[];let browser;
function check(label,condition){if(!condition)throw Error(label);steps.push({label,status:'PASS'});console.log('PASS',label)}
const req=(url,method='GET',headers={})=>new Promise((resolve,reject)=>{
  const u=new URL(url),request=http.request({hostname:u.hostname,port:u.port,path:u.pathname+u.search,method,headers},r=>{
    const chunks=[];r.on('data',b=>chunks.push(b));r.on('end',()=>resolve({status:r.statusCode,headers:r.headers,data:Buffer.concat(chunks)}));
  });request.on('error',reject);request.end();
});
async function frame(page,session,title){
  await page.evaluate(({url,title})=>{
    const f=document.createElement('iframe');f.title=title;f.setAttribute('sandbox','allow-scripts');f.referrerPolicy='no-referrer';f.src=url;
    document.body.append(f);
  },{url:session.url,title});
  return page.frameLocator('iframe[title="'+title+'"]');
}
let result;
try{
  const sessions=[];const parent=await makeTrustedHost(()=>sessions.map(s=>s.origin));all.push(parent);
  const A=await makeFixtureSession({tenant:'A',owner:'alice',ip:'127.0.0.2',studioOrigin:parent.origin,dist});
  sessions.push(A);all.push(A);
  const B=await makeFixtureSession({tenant:'B',owner:'bob',ip:'127.0.0.3',studioOrigin:parent.origin,dist});
  sessions.push(B);all.push(B);
  check('Two tenants get different origins, session IDs and capabilities',
    A.origin!==B.origin && A.id!==B.id && A.prefix!==B.prefix);
  check('Owner A can mint session-view capability',A.grant('alice')===A.url);
  let denied=false;try{A.grant('bob')}catch{denied=true}
  check('Owner B cannot mint owner A capability',denied);
  check('Unauthenticated document path denied',(await req(A.origin+'/index.html')).status===404);
  check('Missing or invalid session capability denied',(await req(A.origin+'/v/'+A.id+'/notatoken/index.html')).status===404);
  const wrong=A.prefix.split('/')[3];
  const swapped=B.prefix.replace(B.prefix.split('/')[3],wrong);
  check('Capability from tenant A rejected for tenant B',(await req(B.origin+swapped+'/index.html')).status===404);
  const home=await req(A.url);
  check('Authorized initial resource permitted with strict headers',
    home.status===200 && home.headers['content-security-policy'].includes("default-src 'none'") &&
    home.headers['content-security-policy'].includes('frame-ancestors '+parent.origin) &&
    home.headers['access-control-allow-origin']==='*' &&
    !home.headers['access-control-allow-credentials'] &&
    !home.headers['set-cookie'] && home.headers['cache-control'].includes('no-store'));
  check('Uncredentialed HEAD supported but range refused',
    (await req(A.url,'HEAD')).status===200 && (await req(A.url,'GET',{Range:'bytes=0-4'})).status===416);
  browser=await chromium.launch({headless:true});const page=await browser.newPage(),errors=[],scripts=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('response',r=>{if(/lazy-.*\.js$/.test(new URL(r.url()).pathname))scripts.push({status:r.status(),url:r.url()})});
  await page.goto(parent.origin);
  const fa=await frame(page,A,'cap-A');
  await fa.locator('#pof-header').waitFor({timeout:20000});
  check('Official Vite React renders via gated session URLs',
    (await fa.locator('#pof-header').innerText()).includes('Vite React: READY'));
  check('Stylesheet decoded from same authorized session',
    await fa.locator('body').evaluate(e=>getComputedStyle(e).backgroundColor==='rgb(248, 250, 252)'));
  await fa.locator('#pof-load').click();
  await fa.locator('#pof-status').getByText(/CHUNK READY/).waitFor({timeout:15000});
  check('Real Vite lazy ESM chunk fetched HTTP 200 through capability gate',
    scripts.some(s=>s.status===200&&s.url.startsWith(A.origin+A.prefix+'/assets/lazy-')));
  check('Vite PNG authorized and decoded',
    await fa.locator('#pof-img').evaluate(async i=>{await i.decode();return i.naturalWidth===2&&i.naturalHeight===2}));
  const isolated=await fa.locator('body').evaluate(()=>{
    let parentDenied=false,storageDenied=false;
    try{void parent.document.querySelector('#secret')}catch{parentDenied=true}
    try{void localStorage.getItem('x')}catch{storageDenied=true}
    return {opaque:origin==='null',parentDenied,storageDenied};
  });
  check('Opaque sandbox denies parent DOM and storage',
    isolated.opaque&&isolated.parentDenied&&isolated.storageDenied);
  const before=B.log.length;
  const noFetch=await fa.locator('body').evaluate(async url=>{
    try{await fetch(url);return false}catch{return true}
  },B.url);
  check('CSP prevents cross-tenant fetch through iframe',noFetch&&B.log.length===before);
  const fb=await frame(page,B,'cap-B');
  await fb.locator('#pof-header').waitFor({timeout:20000});
  check('Second tenant still renders independently',
    (await fb.locator('#pof-header').innerText()).includes('READY'));
  const copied=await req(A.url); // deliberately simulates attacker who stole entire capability URL
  check('CRITICAL NEGATIVE FINDING: stolen URL replays without identity (expected)',
    copied.status===200);
  const assetName=[...A.log].find(x=>/\/assets\/lazy-/.test(x.path))?.path;
  check('Transformed lazy chunk appears in gated manifest',Boolean(assetName));
  B.tamper(assetName);
  check('SHA256 detects changed immutable bytes even with valid capability',
    (await req(B.origin+B.prefix+assetName)).status===409);
  A.revoke();
  check('Revocation blocks previously valid asset URLs',
    (await req(A.url)).status===410&&(await req(A.origin+A.prefix+assetName)).status===410);
  check('Revoking A does not revoke independent B',(await req(B.url)).status===200);
  B.expire();
  check('Expiry blocks previously valid session',(await req(B.url)).status===410);
  check('No uncaught JavaScript errors',errors.length===0);
  await fs.mkdir(path.join(root,'results'),{recursive:true});
  await page.screenshot({path:path.join(root,'results/pof214-two-tenant-preview.png'),fullPage:true});
  await page.close();
  result={status:'PASS_WITH_CRITICAL_SECURITY_LIMITATION',passed:steps.length,
    securityFinding:'Stolen bearer-capability URL is replayable from an unauthenticated HTTP client. NOT suitable for private projects or Production.',
    gates:{syntheticESM:'PASS',opaqueFrame:'PASS',tenantGrant:'PASS',sessionRevocation:'PASS',identityBoundPerAsset:'FAIL_NOT_IMPLEMENTED',privateProduction:'NO_GO'},
    steps,capabilitiesRedacted:true,sessionOrigins:[A.origin,B.origin]};
}catch(e){result={status:'FAIL',passed:steps.length,error:String(e.stack||e),steps};console.error(e.stack||e);process.exitCode=1}
finally{
  await browser?.close().catch(()=>{});
  for(const item of all.reverse())await item.close().catch(()=>{});
  await fs.mkdir(path.join(root,'results'),{recursive:true});
  await fs.writeFile(path.join(root,'results/pof214-proof.json'),JSON.stringify(result,null,2));
}
