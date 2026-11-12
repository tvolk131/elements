'use strict';
let operation, information;
const status = document.querySelector('#status');
const button = document.querySelector('#submit');
button.disabled = true;
async function initialize() {
  information = await (await fetch('/info')).json();
  document.querySelector('#institution').textContent = information.guardian_id + ' · independent approval service';
  operation = JSON.parse(decodeURIComponent(location.hash.slice(1)));
  history.replaceState(null, '', '/');
  if (!information.coordinator_origins.includes(operation.return_origin) || !window.opener) throw new Error('Open this review from the guardian approval queue.');
  const terms = document.createElement('dl');
  const fields = operation.kind === 'federation_rotation'
    ? {Case:operation.id,Action:'Same-chain federation membership rotation',From:operation.source_policy_version,To:operation.target_policy_version,
       Chain:operation.genesis_hash,'Migration transactions':operation.manifest.migrations.length,Expires:new Date(operation.expires_at*1000).toISOString()}
    : {Case:operation.id,Action:operation.kind,Currency:'Test'+operation.currency,Amount:(operation.amount_minor/100).toFixed(2),Beneficiary:operation.destination,Receipt:operation.cash_receipt_id||'—',Chain:operation.genesis_hash,Expires:new Date(operation.expires_at*1000).toISOString()};
  for (const [label, value] of Object.entries(fields)) {
    const dt=document.createElement('dt'), dd=document.createElement('dd'); dt.textContent=label; dd.textContent=value; terms.append(dt,dd);
  }
  document.querySelector('#terms').append(terms);
  document.querySelector('#request').textContent=JSON.stringify(operation,null,2);
  button.disabled=false;
}
initialize().catch(error=>{status.textContent=error.message;});
document.querySelector('#approval').addEventListener('submit', async event=>{
  event.preventDefault(); button.disabled=true; status.textContent='Signing this exact authorization…';
  const password=document.querySelector('#passphrase');
  try {
    const response=await fetch('/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({operation,passphrase:password.value})});
    password.value=''; const signature=await response.json();
    if(!response.ok)throw new Error(signature.error||'Approval refused');
    window.opener.postMessage({type:'institution-approval',operation_id:operation.id,signature},operation.return_origin);
    status.textContent='Authorization signed and returned to the guardian queue. You can close this window.';
  }catch(error){password.value='';status.textContent=error.message;button.disabled=false;}
});
