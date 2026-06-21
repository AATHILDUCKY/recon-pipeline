document.addEventListener('DOMContentLoaded',()=>{
  const monitor=document.querySelector('.scan-monitor');
  if(monitor){const id=monitor.dataset.scanId,log=monitor.querySelector('[data-log]'),status=monitor.querySelector('[data-status]');let prior='';
    const poll=async()=>{try{const r=await fetch(`/api/scans/${id}`,{headers:{Accept:'application/json'}});if(!r.ok)return;const d=await r.json();status.textContent=d.status;if(d.log){log.textContent=d.log;if(d.log!==prior){log.scrollTop=log.scrollHeight;prior=d.log}}if(['complete','failed','cancelled'].includes(d.status)){setTimeout(()=>location.reload(),700);return}}catch(e){}setTimeout(poll,2000)};poll()}
  const tabs=document.querySelectorAll('[data-tab]');tabs.forEach(btn=>btn.addEventListener('click',()=>{tabs.forEach(x=>x.classList.toggle('active',x===btn));document.querySelectorAll('[data-pane]').forEach(x=>x.classList.toggle('hidden',x.dataset.pane!==btn.dataset.tab))}));
  const filter=document.querySelector('[data-filter]');if(filter)filter.addEventListener('input',()=>{const q=filter.value.toLowerCase();document.querySelectorAll('[data-filter-list]>div').forEach(x=>x.hidden=!x.textContent.toLowerCase().includes(q))});
});
