'use strict';
let operation, information;
const status = document.querySelector('#status');
const button = document.querySelector('#submit');
button.disabled = true;
async function initialize() {
  information = await (await fetch('/info')).json();
  document.querySelector('#institution').textContent = 'Operator ' + information.guardian_id.replace(/^institution-/i, '').toUpperCase();
  operation = JSON.parse(decodeURIComponent(location.hash.slice(1)));
  history.replaceState(null, '', '/');
  if (!information.coordinator_origins.includes(operation.return_origin) || !window.opener) throw new Error('Open this review from the network console approval queue.');
  if (operation.kind !== 'federation_rotation') {
    const amount = document.createElement('div'), label = document.createElement('span'), value = document.createElement('strong');
    amount.className = 'amount';
    label.textContent = 'Amount';
    value.textContent = (operation.amount_minor/100).toLocaleString('en-GB',{minimumFractionDigits:2}) + ' UNITED ' + operation.currency;
    amount.append(label, value);
    document.querySelector('#terms').append(amount);
  }
  const terms = document.createElement('dl');
  const fields = operation.kind === 'federation_rotation'
    ? {Action:'Hand over to new network operators',From:operation.source_policy_version,To:operation.target_policy_version,
       'Funds to move':operation.manifest.migrations.length,
       'Approval valid until':new Date(operation.expires_at*1000).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short',timeZone:'UTC'})+' UTC',
       Case:operation.id}
    : {Action:{deposit:'Issue tokens for a bank deposit',transfer:'Payment',redemption:'Withdraw to bank',refund:'Return locked tokens'}[operation.kind]||operation.kind,
       From:operation.display?.from||operation.account_id,
       To:operation.display?.to||operation.destination_name||operation.account_id,
       'Approval valid until':new Date(operation.expires_at*1000).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short',timeZone:'UTC'})+' UTC',
       Case:operation.id};
  for (const [label, value] of Object.entries(fields)) {
    const dt=document.createElement('dt'), dd=document.createElement('dd'); dt.textContent=label; dd.textContent=value; terms.append(dt,dd);
  }
  document.querySelector('#terms').append(terms);
  document.querySelector('#request').textContent=JSON.stringify(operation,null,2);
  if (information.demo_passphrase) {
    // Demo runtimes only: the service offers its own passphrase so a presenter
    // can sign without copying credentials. Signing still happens here.
    document.querySelector('#passphrase').value = information.demo_passphrase;
    status.textContent = 'Demo mode: this operator\u2019s passphrase is filled in.';
  }
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
    status.textContent='Approved and signed. Returning to the console…';
    setTimeout(()=>window.close(),1200);
  }catch(error){password.value='';status.textContent=error.message;button.disabled=false;}
});
