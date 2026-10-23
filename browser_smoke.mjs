import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';

const root=path.dirname(fileURLToPath(import.meta.url));
const req=createRequire(path.join(root,'fixtures/vite/package.json'));
const {chromium}=req('@playwright/test');
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png'};
const notes=[];
function assert(ok,message){if(!ok)throw Error(message)}
function pass(name){notes.push({name,result:'PASS'});console.log('PASS: '+name)}
async function serve(folder){
  const dir=path.resolve(root,folder);
  const server=http.createServer(async(request,response)=>{
    try{
      if(request.method!=='GET'){response.writeHead(405).end();return}
      const pathname=decodeURIComponent(new URL(request.url,'http://localhost').pathname);
      const target=path.resolve(dir,'.'+(pathname==='/'?'/index.html':pathname));
      if(!target.startsWith(dir+path.sep)){response.writeHead(403).end();return}
      const body=await fs.readFile(target);
      response.writeHead(200,{'Content-Type':mime[path.extname(target)]||'application/octet-stream','Access-Control-Allow-Origin':'*','Cross-Origin-Resource-Policy':'cross-origin','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; script-src "+('http://127.0.0.1:'+server.address().port)+"; style-src "+('http://127.0.0.1:'+server.address().port)+" 'unsafe-inline'; img-src "+('http://127.0.0.1:'+server.address().port)+" data: blob:; font-src "+('http://127.0.0.1:'+server.address().port)+" data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"});
      response.end(body);
    }catch(error){response.writeHead(404).end()}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {url:'http://127.0.0.1:'+server.address().port+'/',close:()=>new Promise(resolve=>server.close(resolve))}
}
let browser=null;
const servers=[];
let failure=null;
const completed=[];
try{
  const vite=await serve('fixtures/vite/dist');servers.push(vite);
  const expo=await serve('fixtures/expo/dist');servers.push(expo);
  const host=await serve('host');servers.push(host);
  browser=await chromium.launch({headless:true});
  for(const [kind,preview] of [['vite',vite],['expo',expo]]){
    const page=await browser.newPage();
    const errors=[];const responses=[];
    page.on('pageerror',error=>errors.push(error.message));
    page.on('response',response=>{if(/\.m?js(?:\?|$)/.test(response.url()))responses.push({url:response.url(),status:response.status()})});
    try{
      await page.goto(host.url,{waitUntil:'domcontentloaded'});
      await page.evaluate(url=>{
        const frame=document.createElement('iframe');
        frame.title='isolated-preview';
        frame.setAttribute('sandbox','allow-scripts');
        frame.setAttribute('referrerpolicy','no-referrer');
        frame.src=url;
        document.body.append(frame);
      },preview.url);
      const frame=page.frameLocator('iframe[title="isolated-preview"]');
      if(kind==='vite'){
        await frame.locator('#pof-header').waitFor({timeout:20000});
        assert((await frame.locator('#pof-header').innerText()).includes('Vite React: READY'),'Vite render marker');
        pass('Vite official render');
        const before=new Set(responses.map(x=>x.url));
        await frame.locator('#pof-load').click();
        await frame.locator('#pof-status').getByText(/CHUNK READY/).waitFor({timeout:15000});
        pass('Vite React dynamic import state');
        assert(responses.some(x=>x.status===200&&!before.has(x.url)&&/\/assets\/[^/]+\.js(?:\?|$)/.test(x.url)),'Vite dynamic chunk was not fetched HTTP 200');
        pass('Vite dynamic chunk HTTP 200');
        assert(await frame.locator('#pof-img').evaluate(async img=>{await img.decode();return img.naturalWidth===2&&img.naturalHeight===2}),'Vite PNG decode');
        pass('Vite PNG asset decode');
      }else{
        await frame.getByText('Expo Web official build fixture').waitFor({timeout:20000});
        pass('Expo official render');
        await frame.getByText('Count: 0').click();
        await frame.getByText('Count: 1').waitFor({timeout:12000});
        pass('Expo counter interaction');
        const el=frame.locator('[data-testid="pof-expo-img"]').first();
        await el.waitFor({timeout:15000});
        assert(await el.evaluate(async node=>{
          for(const img of [node,...node.querySelectorAll('img')]){
            if(img instanceof HTMLImageElement){
              try{await img.decode()}catch{continue}
              if(img.naturalWidth===2&&img.naturalHeight===2)return true
            }
          }
          for(const item of [node,...node.querySelectorAll('*')]){
            const bg=getComputedStyle(item).backgroundImage;
            const match=bg.match(/url\(["']?(.*?)["']?\)/);
            if(!match)continue;
            const img=new Image();img.src=match[1];
            try{await img.decode()}catch{continue}
            if(img.naturalWidth===2&&img.naturalHeight===2)return true
          }
          return false;
        }),'Expo PNG decode');
        pass('Expo PNG image decode');
      }
      const isolation=await frame.locator('body').evaluate(()=>{
        let parentDenied=false,storageDenied=false;
        try{void window.parent.document.getElementById('host-secret')}catch{parentDenied=true}
        try{window.localStorage.getItem('probe')}catch{storageDenied=true}
        return {parentDenied,storageDenied,opaque:window.origin==='null'}
      });
      assert(isolation.parentDenied&&isolation.storageDenied&&isolation.opaque,kind+' iframe isolation failed');
      pass(kind+' opaque sandbox DOM and storage denial');
      assert(errors.length===0,kind+' browser JS errors: '+errors.join(' | '));
      pass(kind+' no pageerror');
      completed.push(kind);
    }finally{await page.close()}
  }
  assert(completed.join(',')==='vite,expo','Both previews were not exercised');
}catch(err){failure=String(err.stack||err);console.error(failure)}
finally{
  if(browser)await browser.close().catch(()=>{});
  await Promise.all(servers.map(s=>s.close().catch(()=>{})));
}
await fs.mkdir(path.join(root,'results'),{recursive:true});
await fs.writeFile(path.join(root,'results/browser_smoke.json'),JSON.stringify({completed,pass:notes.length,failed:failure,results:notes},null,2));
if(failure)process.exitCode=1;
