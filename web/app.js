'use strict';
const base=location.pathname.replace(/\/$/,'');
let csrf='',saved=[],dirty=false,polling=false;
const $=id=>document.getElementById(id);
async function api(path,body){
 const response=await fetch(base+'/api/'+path,{method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin'});
 let value;try{value=await response.json()}catch{throw new Error('The host returned an unexpected response. Check routing and try again.')}
 if(!response.ok){if(response.status===401&&path!=='login')showLogin();throw new Error(value.error||'Request failed.')}return value;
}
function notice(text,error=false){$('notice').textContent=text;$('notice').className='notice'+(error?' error':'');$('notice').hidden=!text;}
function showLogin(){$('workspace').hidden=true;$('login').hidden=false;csrf='';}
function view(name){for(const el of document.querySelectorAll('.view'))el.hidden=el.id!=='view-'+name;for(const el of document.querySelectorAll('.nav')){el.classList.toggle('active',el.dataset.view===name);if(el.dataset.view===name)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}const titles={proxies:['Your proxies.','One workspace. Every connection in reach.','Proxies'],links:['Connection links.','A direct line to your next conversation.','Connection links'],setup:['Make yourself at home.','A few host settings, then you’re ready.','Host setup']};$('page-title').textContent=titles[name][0];$('page-description').textContent=titles[name][1];$('breadcrumb').textContent=titles[name][2];}
document.querySelectorAll('[data-view]').forEach(el=>el.addEventListener('click',()=>view(el.dataset.view)));
function renumber(){document.querySelectorAll('.profile').forEach((el,i)=>{el.querySelector('.profile-number').textContent='PROFILE '+String(i+1).padStart(2,'0');for(const input of el.querySelectorAll('input'))input.id=input.className+'-'+i;});}
function addProfile(p={}){
 if(document.querySelectorAll('.profile').length>=16){notice('Up to 16 profiles are supported.',true);return;}
 const item=$('profile-template').content.firstElementChild.cloneNode(true);
 item.querySelector('.domain').value=p.domain||'';item.querySelector('.secret').value=p.secret||'';item.querySelector('.sponsor').value=p.tag||'';
 item.querySelector('.remove').addEventListener('click',()=>{if(document.querySelectorAll('.profile').length===1){notice('Keep at least one profile, or use Disable proxy.',true);return;}item.remove();dirty=true;renumber();});
 item.querySelector('.generate').addEventListener('click',async event=>{const button=event.currentTarget;button.disabled=true;try{const result=await api('secret',{});item.querySelector('.secret').value=result.secret;dirty=true;}catch(e){notice(e.message,true)}finally{button.disabled=false}});
 item.addEventListener('input',()=>dirty=true);$('profiles').append(item);renumber();
}
function renderLinks(running){
 $('links').replaceChildren();if(!saved.length){const el=document.createElement('p');el.className='empty';el.textContent='No links yet. Add your first profile and deploy it.';$('links').append(el);return;}
 for(const [index,p] of saved.entries()){
 const article=document.createElement('article');article.className='connection';const title=document.createElement('h3');title.textContent=String(index+1).padStart(2,'0')+' / '+p.domain;const code=document.createElement('code');const link='tg://webproxy?server='+encodeURIComponent(p.domain)+'&secret=dd'+p.secret;code.textContent=link;
 const actions=document.createElement('div');actions.className='connection-actions';const copy=document.createElement('button');copy.className='secondary';copy.textContent='Copy full link';copy.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(link);copy.textContent='Copied ✓';setTimeout(()=>copy.textContent='Copy full link',1800)}catch{const range=document.createRange();range.selectNodeContents(code);getSelection().removeAllRanges();getSelection().addRange(range);notice('Link selected. Copy it using your device’s copy command.')}});
 const open=document.createElement('a');open.href=link;open.textContent='Open Telegram ↗';actions.append(copy,open);article.append(title,code,actions);
 if(!running){const note=document.createElement('small');note.textContent='Proxy is not running. Deploy it before using this link.';article.append(note)}$('links').append(article);
 }
}
async function refresh(rebuild=false){
 const s=await api('state');csrf=s.csrf;saved=s.profiles||[];
 $('login').hidden=true;$('workspace').hidden=false;
 $('profile-count').textContent=saved.length;$('nav-count').textContent=saved.length;
 $('endpoint').textContent=new URL(s.public_url).hostname;
 $('last-deployed').textContent=s.updated?new Date(s.updated).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'Not yet';
 const busy=['deploying','stopping','restoring'].includes(s.job);
 $('status').classList.toggle('live',s.running&&!busy);$('status').lastElementChild.textContent=busy?(s.job==='deploying'?'Deploying…':s.job==='stopping'?'Stopping…':'Restoring…'):s.running?'Core ready':'Not running';
 for(const id of ['deploy','stop','add-profile'])$(id).disabled=busy;
 for(const el of document.querySelectorAll('#profiles input,#profiles button'))el.disabled=busy;
 $('deploy').firstChild.textContent=busy?'Working… ':'Deploy proxy ';
 if(rebuild||!dirty&&!busy){$('profiles').replaceChildren();for(const p of saved.length?saved:[{domain:new URL(s.public_url).hostname}])addProfile(p);dirty=false;}
 renderLinks(s.running);
 if(busy){notice('Applying configuration. This may take a minute on the first deployment.');if(!polling){polling=true;pollJob()}}
 else if(s.job.startsWith('Deployment failed:')||s.job.startsWith('Restore failed:'))notice(s.job,true);
 return s;
}
async function pollJob(){
 try{while(!$('workspace').hidden){await new Promise(resolve=>setTimeout(resolve,2000));const s=await refresh(false);if(!['deploying','stopping','restoring'].includes(s.job)){if(s.job==='deployed'){dirty=false;await refresh(true);notice('Core deployed. Check your host’s HTTPS routing, then open Connection links.')}else if(s.job==='disabled')notice('Proxy disabled. Your profiles and links are retained.');break;}}}catch(e){notice(e.message,true)}finally{polling=false;}
}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();$('sign-in').disabled=true;$('login-error').textContent='';try{const s=await api('login',{password:$('password').value});csrf=s.csrf;$('password').value='';dirty=false;await refresh(true)}catch(e){$('login-error').textContent=e.message}finally{$('sign-in').disabled=false}});
$('logout').addEventListener('click',async()=>{try{await api('logout',{});showLogin()}catch(e){notice(e.message,true)}});
$('add-profile').addEventListener('click',()=>{addProfile();dirty=true;document.querySelector('.profile:last-child .domain').focus()});
$('deploy-form').addEventListener('submit',async e=>{
 e.preventDefault();const profiles=[...document.querySelectorAll('.profile')].map(el=>({domain:el.querySelector('.domain').value.trim(),secret:el.querySelector('.secret').value.trim(),tag:el.querySelector('.sponsor').value.trim()}));
 if(!confirm('Apply these profiles? Existing proxy sessions may reconnect. Changing or removing a Secret invalidates its previous links.'))return;
 $('deploy').disabled=true;try{await api('deploy',{profiles});dirty=false;await refresh(false)}catch(e){notice(e.message,true);$('deploy').disabled=false;}
});
$('stop').addEventListener('click',async()=>{if(!confirm('Disable the proxy? Saved profiles and Secrets will be kept.'))return;try{await api('stop',{});await refresh(false)}catch(e){notice(e.message,true)}});
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue=''}});
refresh(true).catch(e=>{showLogin();if(!e.message.includes('Sign in'))$('login-error').textContent=e.message});
