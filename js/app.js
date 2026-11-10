/* PhishGuard: detection engine (URL + text analysis) and UI logic */
const $=s=>document.querySelector(s),esc=s=>s.replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])),sleep=ms=>new Promise(r=>setTimeout(r,ms));
const BR=["paypal","google","amazon","microsoft","apple","facebook","netflix","instagram","paytm","hdfc","icici","sbi","flipkart","whatsapp","linkedin"],KW=["login","signin","verify","secure","account","update","confirm","banking","wallet","password","suspend","unlock","bonus","kyc","otp","claim"],BAD=["xyz","top","tk","ml","ga","cf","gq","click","zip","icu","work","buzz","rest"],SH=["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy"];
const leet=s=>s.replace(/0/g,"o").replace(/1/g,"l").replace(/3/g,"e").replace(/5/g,"s").replace(/rn/g,"m").replace(/vv/g,"w");
function lev(a,b){const d=[...Array(a.length+1)].map((_,i)=>[i,...Array(b.length).fill(0)]);for(let j=1;j<=b.length;j++)d[0][j]=j;for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]==b[j-1]?0:1));return d[a.length][b.length]}
const sc=F=>Math.min(100,F.reduce((a,f)=>a+f.w,0));
function aURL(raw){let u;try{u=new URL(/^\w+:\/\//.test(raw)?raw:"https://"+raw)}catch(e){return null}
const h=u.hostname.toLowerCase(),L=h.split("."),p=(u.pathname+u.search).toLowerCase(),tld=L[L.length-1],F=[],add=(s,t,d,w)=>F.push({s,t,d,w});
u.protocol=="https:"?add("ok","HTTPS in use","Traffic is encrypted, though HTTPS alone does not prove a site is safe.",0):add("h","No HTTPS","Served over plain HTTP, so data can be intercepted.",15);
if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h))add("h","IP address as host","Real brands use domain names, not raw IPs.",30);
if(raw.includes("@"))add("h","@ symbol in URL","Browsers ignore everything before @, a classic disguise.",20);
if(h.includes("xn--"))add("h","Punycode domain","May hide look-alike Unicode characters.",25);
if(raw.length>75)add("m","Very long URL",`${raw.length} characters, often used to bury the real destination.`,10);
if(L.length>3)add("m","Many subdomains",`${L.length-2} subdomain levels stacked to fake a trusted name.`,12);
if((h.match(/-/g)||[]).length>=2)add("m","Multiple hyphens","Hyphen-stuffed domains are common in fake sites.",10);
if(BAD.includes(tld))add("h","Risky TLD",`.${tld} domains are heavily abused by scammers.`,18);
if(SH.includes(h))add("m","URL shortener","Hides the final destination.",15);
const kw=KW.filter(k=>(h+p).includes(k));if(kw.length)add(kw.length>1?"h":"m","Sensitive keywords","Found: "+kw.join(", "),Math.min(24,kw.length*8));
const reg=L.length>2&&/^(co|com|org|net|gov|ac)$/.test(L[L.length-2])&&tld.length==2?L[L.length-3]:L[L.length-2]||"";let hit=null;
h.split(/[.-]/).forEach(t=>{const n=leet(t);BR.forEach(b=>{if(t!=b&&(n==b||(b.length>4&&lev(n,b)==1)))hit=hit||[t,b]})});
if(hit)add("h","Brand look-alike",`“${hit[0]}” imitates ${hit[1]}.`,35);else{const b=BR.find(b=>h.includes(b)&&reg!=b);if(b)add("h","Brand in wrong domain",`Mentions ${b} but the real domain is ${reg}.`,28)}
if(!/^\d/.test(h)&&(h.match(/\d/g)||[]).length>=4)add("m","Digit-heavy host","Random digits suggest an auto-generated domain.",8);
if(u.port&&!["80","443"].includes(u.port))add("m","Unusual port",`Port ${u.port} is rare for real sites.`,8);
if((raw.match(/%[0-9a-f]{2}/gi)||[]).length>=3)add("m","Heavy URL encoding","Used to obfuscate the real path.",8);
if(/[?&](url|redirect|next|goto)=http/.test(p))add("m","Open-redirect pattern","Forwards you on to another site.",10);
if(!F.some(f=>f.w))add("ok","Clean structure","No suspicious patterns found in this URL.",0);
return{F,host:h}}
const R=[[/urgent|immediately|act now|within \d+ ?(hours?|hrs?|minutes?)|final notice|last warning|expires?/gi,"Urgency pressure","Rushing stops you from thinking.",8,24],[/suspend|blocked|locked|deactivat|terminated|legal action|unauthori[sz]ed/gi,"Threat language","Fear of losing access is a classic lever.",8,20],[/password|otp|\bpin\b|cvv|card number|aadhaar|\bpan\b|kyc|verify your/gi,"Asks for sensitive data","Real banks never ask for these by message.",12,32],[/\bwon\b|winner|prize|lottery|reward|cashback|gift card|\bfree\b|congratulations/gi,"Too-good-to-be-true reward","Prize bait for clicks or data.",10,20],[/dear (customer|user|member|sir|madam|client)/gi,"Generic greeting","Mass-sent scams do not know your name.",8,8]];
function aTxt(t){const F=[],add=(s,t,d,w)=>F.push({s,t,d,w});
R.forEach(([re,n,d,w,cap])=>{const x=new Set((t.match(re)||[]).map(s=>s.toLowerCase()));if(x.size){const v=Math.min(cap,x.size*w);add(v>=15?"h":"m",n,`Matched: ${[...x].slice(0,4).join(", ")}. ${d}`,v)}});
(t.match(/(https?:\/\/|www\.)[^\s]+/gi)||[]).slice(0,3).forEach(l=>{const r=aURL(l.replace(/[.,;)]+$/,""));if(r){const s=sc(r.F);if(s>20)add(s>45?"h":"m","Risky link: "+r.host,`Link scores ${s}/100: ${r.F.filter(f=>f.w).map(f=>f.t).slice(0,3).join(", ")}.`,Math.min(35,Math.round(s*.6)))}});
const lt=t.replace(/[^a-z]/gi,"");if(lt.length>25&&(t.match(/[A-Z]/g)||[]).length/lt.length>.5)add("m","SHOUTING in CAPS","Aggressive formatting is a pressure tactic.",8);
if((t.match(/!/g)||[]).length>=3)add("m","Excess exclamation marks","Hype language is common in scams.",6);
if(!F.length)add("ok","No scam patterns","Tone and content look normal. Still verify unknown senders.",0);return{F}}
let mode="url",HI=[];try{HI=JSON.parse(localStorage.getItem("pg")||"[]")}catch(e){}
const S={url:["http://paypa1-secure-login.verify-account.xyz/signin?id=88213","https://www.google.com","http://192.168.4.21/bank/update@hdfc-kyc.top"],msg:["URGENT: Your SBI account will be blocked within 24 hours! Update KYC now: http://sbi-kyc-update.top/login and share OTP","Hey, are we still meeting at 5 for the project demo? Notes are in the shared drive."]};
function chips(){$("#ch").innerHTML="Try: ";S[mode].forEach((s,i)=>{const b=document.createElement("button");b.className="chip";b.textContent=["⚠️ Phish sample","✅ Safe sample","🚨 IP + @ trick"][mode=="msg"&&i==1?1:i];b.onclick=()=>{$("#in").value=s;go()};$("#ch").append(b)})}
document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{mode=b.dataset.m;document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("on",x==b));$("#in").placeholder=mode=="url"?"Paste a suspicious link…":"Paste the email or SMS text…";$("#in").rows=mode=="url"?2:5;chips()});
function cnt(el,to,ms=900){const t0=performance.now();(function f(t){const p=Math.min(1,(t-t0)/ms);el.textContent=Math.round(to*(1-Math.pow(1-p,3)));if(p<1)requestAnimationFrame(f)})(t0)}
async function go(){const v=$("#in").value.trim(),b=$("#go");if(!v){$("#in").focus();return}
const r=mode=="url"?aURL(v):aTxt(v);$("#res").hidden=false;$("#out").hidden=true;b.disabled=true;$("#sc").classList.add("sc");$("#res").scrollIntoView({behavior:"smooth",block:"center"});
const T=$("#term");T.textContent="";const steps=mode=="url"?["resolving host structure","extracting URL features","checking brand look-alikes","scoring TLD and keyword risk","running risk model"]:["tokenizing message","detecting urgency and threats","scanning for credential requests","analysing embedded links","running risk model"];
for(const s of steps){T.textContent+="> "+s+" …\n";await sleep(280)}
$("#sc").classList.remove("sc");b.disabled=false;
if(!r){T.textContent+="✖ That does not look like a valid URL.";return}
T.textContent+="✔ analysis complete";const s=sc(r.F),k=s<25?["safe","Looks Safe","✅","No major red flags. Still, only enter passwords on sites you reached yourself."]:s<55?["warn","Suspicious","⚠️","Be careful. Do not enter details until you verify the sender through an official channel."]:["bad","Dangerous","🚨","Do not click or reply. Report it at cybercrime.gov.in or call 1930 (India)."];
$("#out").hidden=false;$("#g").className="g "+(k[0]=="safe"?"":k[0]);$("#fg").style.strokeDashoffset=283*(1-s/100);cnt($("#gn"),s);$("#vd").textContent=k[2]+" "+k[1];$("#act").textContent=k[3];
$("#fl").innerHTML=r.F.sort((a,b)=>b.w-a.w).map((f,i)=>`<div class="f ${f.s}" style="animation-delay:${i*.09}s"><b>${esc(f.t)}</b>${f.w?`<i>+${f.w}</i>`:""}<p>${esc(f.d)}</p></div>`).join("");
HI.unshift({m:mode,v:v.slice(0,80),s,k:k[0],e:k[2]});HI=HI.slice(0,30);try{localStorage.setItem("pg",JSON.stringify(HI))}catch(e){}dash()}
function dash(){const n=HI.length,c={safe:0,warn:0,bad:0};HI.forEach(h=>c[h.k]++);cnt($("#t1"),n);cnt($("#t2"),c.warn+c.bad);cnt($("#t3"),n?Math.round(HI.reduce((a,h)=>a+h.s,0)/n):0);
$("#bars").innerHTML=[["Safe","safe","ok"],["Suspicious","warn","wn"],["Dangerous","bad","dn"]].map(([l,k,v])=>`<div class="bar"><span>${l}</span><div style="width:${n?c[k]/n*100:0}%;background:var(--${v})"></div>${c[k]}</div>`).join("");
$("#hist").innerHTML=n?HI.slice(0,6).map((h,i)=>`<div class="hi" data-i="${i}"><span>${h.e} ${esc(h.v)}</span><span>${h.s}/100</span></div>`).join(""):`<p style="color:var(--mut);text-align:center">No scans yet. Try a sample above!</p>`}
$("#hist").onclick=e=>{const r=e.target.closest(".hi");if(r){const h=HI[r.dataset.i];document.querySelector(`.tab[data-m=${h.m}]`).click();$("#in").value=h.v;go()}};
$("#go").onclick=go;$("#in").onkeydown=e=>{if(e.key=="Enter"&&(mode=="url"||e.ctrlKey)){e.preventDefault();go()}};
$("#tg").onclick=()=>{const d=document.documentElement,dk=d.dataset.theme?d.dataset.theme=="dark":matchMedia("(prefers-color-scheme:dark)").matches;d.dataset.theme=dk?"light":"dark"};
document.querySelectorAll(".card").forEach(c=>c.addEventListener("pointermove",e=>{const r=c.getBoundingClientRect();c.style.setProperty("--mx",e.clientX-r.left+"px");c.style.setProperty("--my",e.clientY-r.top+"px")}));
document.querySelectorAll("[data-to]").forEach(e=>cnt(e,+e.dataset.to,1400));chips();dash();
const cv=$("#bg"),cx=cv.getContext("2d");let W,Hh,dr;function rs(){W=cv.width=innerWidth;Hh=cv.height=innerHeight;dr=Array.from({length:Math.ceil(W/18)},()=>Math.random()*Hh/18)}rs();addEventListener("resize",rs);
if(!matchMedia("(prefers-reduced-motion:reduce)").matches)setInterval(()=>{cx.globalCompositeOperation="destination-out";cx.fillStyle="rgba(0,0,0,.14)";cx.fillRect(0,0,W,Hh);cx.globalCompositeOperation="source-over";cx.fillStyle="rgb("+getComputedStyle(document.documentElement).getPropertyValue("--rain")+")";cx.font="14px monospace";dr.forEach((y,i)=>{cx.fillText(Math.random()>.5?"1":"0",i*18,y*18);dr[i]=y*18>Hh&&Math.random()>.975?0:y+1})},70);
