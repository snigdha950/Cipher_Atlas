const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
let lastScan = null;
let lastProbe = null;
let probeHistory = [];

function toast(msg){ const el=$('#toast'); el.textContent=msg; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2300); }
function go(view){
  $$('.view').forEach(v=>v.classList.remove('active'));
  $$('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===view));
  $(`#view-${view}`).classList.add('active');
  const titles={overview:'Evidence before migration',inventory:'Cryptographic inventory',rehearsal:'Migration rehearsal',evidence:'Evidence & limits'};
  $('#pageTitle').textContent=titles[view];
}
$$('.nav').forEach(n=>n.onclick=()=>go(n.dataset.view));
$$('[data-go]').forEach(b=>b.onclick=()=>go(b.dataset.go));
function esc(x){return String(x??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}

function renderScan(d){
  lastScan=d;
  $('#mFindings').textContent=d.findings.length;
  $('#mCoverage').textContent=`${d.coverage.percent}%`;
  $('#mCoverageText').textContent=d.coverage.status==='COMPLETE'?'all files analyzed':'partial scan · inspect limits';
  $('#mContracts').textContent=d.contracts.length;
  $('#mUnknown').textContent=d.contracts.length;
  const cb=$('#coverageBadge'); cb.textContent=`${d.coverage.status} · ${d.coverage.percent}%`; cb.style.background=d.coverage.status==='COMPLETE'?'#ecfdf5':'#fff8e7'; cb.style.color=d.coverage.status==='COMPLETE'?'#087a55':'#a15c00';
  $('#findingsBody').innerHTML=d.findings.length?d.findings.map(f=>`<tr><td><strong>${esc(f.algorithm)}</strong><small>${esc(f.path)}${f.line?`:${f.line}`:''}${f.version?` · v${esc(f.version)}`:''}</small></td><td>${esc(f.purpose)}${f.confidence!=='CONFIRMED'?`<br><span class="badge amber">${esc(f.confidence)}</span>`:''}</td><td><span class="evidence-chip">${esc(f.evidence)}</span></td><td>${esc(f.concern)}</td></tr>`).join(''):'<tr><td colspan="4">No supported findings.</td></tr>';
  $('#contractsList').innerHTML=d.contracts.length?d.contracts.map(c=>`<div class="contract"><div><strong>${esc(c.producer)}</strong><small>${esc(c.current)}</small></div><div class="edge">${esc(c.purpose)}<br>→ ${esc(c.target)}</div><div><strong>${esc(c.consumer)}</strong><small>${esc(c.protocol)}</small></div></div>`).join(''):'<p class="muted">No contract manifest found. Dependency inference remains unknown.</p>';
  const cv=d.coverage;
  const rows=[['Total files',cv.total_files],['Analyzed',cv.analyzed_files],['Unsupported',cv.unsupported_files],['Parse failures',cv.parse_failures],['Artifact SHA-256',d.artifact_sha256.slice(0,20)+'…']];
  $('#coverageDetails').innerHTML=rows.map(([k,v])=>`<div class="detail-row"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')+(d.errors?.length?`<div class="error-box"><strong>Parser issues</strong>${d.errors.map(e=>`<small>${esc(e.path)} · ${esc(e.error)}</small>`).join('')}</div>`:'');
  $('#healthBadge').textContent=cv.status; $('#healthBadge').className='badge '+(cv.status==='COMPLETE'?'green':'amber');
}

async function scanSample(){ try{const r=await fetch('/api/sample-scan'); if(!r.ok)throw new Error(await r.text()); renderScan(await r.json()); toast('Sample scanned');}catch(e){toast('Scan failed');console.error(e);} }
$('#sampleBtn').onclick=scanSample;
$('#zipInput').onchange=async e=>{const f=e.target.files[0];if(!f)return;const fd=new FormData();fd.append('file',f);toast('Scanning…');try{const r=await fetch('/api/scan',{method:'POST',body:fd});const d=await r.json();if(!r.ok)throw new Error(d.detail||'scan failed');renderScan(d);go('inventory');toast('Static scan complete');}catch(err){toast(err.message);}finally{e.target.value='';}};

function stateClass(s){return s==='BLOCKED'?'blocked':s==='VALIDATED_IN_TEST_ENV'?'validated':s==='INCONCLUSIVE'?'inconclusive':'ready';}
function scenarioLabel(client, config){ const c={"openssl-3.0.13":"OpenSSL 3.0.13","openssl-1.1.1w":"OpenSSL 1.1.1w","openssl-3.5.4":"OpenSSL 3.5.4","local-system-openssl":"Local OpenSSL"}[client]||client; const p={hybrid_with_classical_fallback:'hybrid + fallback',hybrid_only:'hybrid required',classical_only:'classical only'}[config]||config; return `${c} · ${p}`; }

function renderHistory(){
  $('#historyCount').textContent=`${probeHistory.length} run${probeHistory.length===1?'':'s'}`;
  if(!probeHistory.length){$('#historyList').innerHTML='<p class="muted">Run two scenarios to show the plan changing from evidence.</p>';return;}
  $('#historyList').innerHTML=probeHistory.slice(-4).reverse().map((h,i)=>`<div class="history-item"><div class="history-index">${probeHistory.length-i}</div><div><strong>${esc(h.label)}</strong><small>${esc(h.decision.state)} · observed ${esc(h.evidence.negotiated_group||'none')}</small></div><span class="badge ${h.decision.state==='VALIDATED_IN_TEST_ENV'?'green':h.decision.state==='BLOCKED'?'amber':''}">${esc(h.evidence.mode||'')}</span></div>`).join('');
}

function renderProbe(d, meta){
  lastProbe={...d,meta};
  const ev=d.evidence||{}, dec=d.decision||{};
  const st=$('#decisionState'); st.textContent=dec.state||'INCONCLUSIVE'; st.className='decision-state '+stateClass(dec.state);
  $('#decisionHeadline').textContent=dec.headline||'No decision'; $('#decisionReason').textContent=dec.reason||'';
  $('#obsConnection').textContent=ev.handshake_ok===true?'SUCCESS':ev.handshake_ok===false?'FAILED':'—'; $('#obsGroup').textContent=ev.negotiated_group||'—';
  $('#modeBadge').textContent=(ev.mode||'NO EVIDENCE').replaceAll('_',' ');
  $('#actions').innerHTML=(dec.actions||[]).map((a,i)=>`<div class="action"><strong>${i+1}.</strong> ${esc(a)}</div>`).join('');
  const source=ev.source_file||ev.command||'Local loopback probe'; const scope=ev.openssl_version||ev.scope||'—';
  $('#proofSummary').innerHTML=`<div><small>Scenario</small><strong>${esc(meta.label)}</strong></div><div><small>Source</small><strong>${esc(source)}</strong></div><div><small>Scope</small><strong>${esc(scope)}</strong></div>`;
  $('#rawEvidence').textContent=JSON.stringify({scenario:meta,evidence:ev,decision:dec},null,2);
  $('#downloadEvidence').disabled=false;
  probeHistory.push({label:meta.label,evidence:ev,decision:dec}); renderHistory();
}

async function runProbe(){
  const btn=$('#probeBtn'); btn.disabled=true; btn.textContent='Running probe…';
  const client=$('#clientSelect').value, config=$('#configSelect').value;
  try{
    const r=await fetch('/api/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client,server_config:config})});
    const d=await r.json(); if(!r.ok)throw new Error(d.detail||'probe failed');
    renderProbe(d,{client,server_config:config,label:scenarioLabel(client,config),run_at:new Date().toISOString()});
    toast(d.evidence.mode==='LIVE_LOCAL'?'Live probe complete':'Measured evidence replayed');
  }catch(e){toast('Probe failed');console.error(e);}finally{btn.disabled=false;btn.textContent='Run compatibility probe';}
}
$('#probeBtn').onclick=runProbe;
$$('.challenge').forEach(b=>b.onclick=()=>{$('#clientSelect').value=b.dataset.client;$('#configSelect').value=b.dataset.config;runProbe();});
$('#toggleRaw').onclick=()=>{const el=$('#rawEvidence');el.classList.toggle('hidden');$('#toggleRaw').textContent=el.classList.contains('hidden')?'Show raw evidence':'Hide raw evidence';};
$('#downloadEvidence').onclick=()=>{if(!lastProbe)return;const blob=new Blob([JSON.stringify(lastProbe,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`cipheratlas-evidence-${Date.now()}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);};

async function loadProfiles(){try{const r=await fetch('/api/profiles');const d=await r.json();$('#profilesList').innerHTML=d.profiles.map(p=>`<div class="profile"><div><strong>${esc(p.id)}</strong><small>${esc(p.display)}</small></div><div><span class="badge ${p.ml_kem?'green':'amber'}">ML-KEM ${p.ml_kem?'yes':'no'}</span> <span class="badge ${p.ml_dsa?'green':'amber'}">ML-DSA ${p.ml_dsa?'yes':'no'}</span></div></div>`).join('');}catch(e){$('#profilesList').innerHTML='<p class="muted">Evidence profiles unavailable.</p>';}}

scanSample(); loadProfiles(); renderHistory();
