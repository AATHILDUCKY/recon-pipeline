document.addEventListener('DOMContentLoaded',()=>{
  const monitor=document.querySelector('.scan-monitor');
  const targetStatusPriority={running:0,queued:1,failed:2,complete:3,cancelled:4,'':5};
  const targetStatusRank=status=>targetStatusPriority[status||'']??targetStatusPriority[''];
  const targetRowPriority=row=>targetStatusRank(row.dataset.status);
  const targetRowText=row=>(row.dataset.search||row.textContent||'').toLowerCase();
  const sortTargetRows=panel=>{
    const rows=[...panel.querySelectorAll('[data-target-row]')];
    if(!rows.length)return;
    const parent=rows[0].parentElement;
    rows.sort((a,b)=>targetRowPriority(a)-targetRowPriority(b)||(b.dataset.activity||'').localeCompare(a.dataset.activity||'')||targetRowText(a).localeCompare(targetRowText(b)));
    rows.forEach(row=>parent.appendChild(row));
  };
  const filterTargetPanel=panel=>{
    const search=panel.querySelector('[data-target-search]'),status=panel.querySelector('[data-status-filter]');
    const query=(search?.value||'').trim().toLowerCase(),selected=status?.value||'';
    panel.querySelectorAll('[data-target-row]').forEach(row=>{
      row.hidden=!!(query&&!targetRowText(row).includes(query))||!!(selected&&row.dataset.status!==selected);
    });
    sortTargetRows(panel);
  };
  const refreshTargetPanels=()=>document.querySelectorAll('.target-panel').forEach(filterTargetPanel);
  if(document.querySelector('.sidebar')&&window.EventSource){
    const params=monitor?`?scan_id=${encodeURIComponent(monitor.dataset.scanId)}`:'';
    const stream=new EventSource(`/api/events${params}`);
    const setConnectionState=(connected)=>document.querySelectorAll('[data-stream-state]').forEach(el=>{el.classList.toggle('offline',!connected);el.lastChild.textContent=connected?' Live':' Reconnecting…'});
    stream.addEventListener('open',()=>setConnectionState(true));stream.addEventListener('error',()=>setConnectionState(false));
    stream.addEventListener('workspace',event=>{
      const data=JSON.parse(event.data);setConnectionState(true);
      document.querySelectorAll('[data-live-metric]').forEach(el=>el.textContent=data.totals[el.dataset.liveMetric]||0);
      const projectStatuses=new Map();
      data.latest.forEach(scan=>{
        const activity=scan.finished_at||scan.started_at||scan.created_at||'';
        document.querySelectorAll(`[data-target-id="${scan.target_id}"]`).forEach(row=>{row.dataset.status=scan.status;row.dataset.activity=activity;const badge=row.querySelector('[data-target-status]');if(badge){badge.className=`status ${scan.status}`;badge.querySelector('[data-status-text]').textContent=scan.status}});
        if(scan.project_id){
          const current=projectStatuses.get(scan.project_id);
          if(!current||targetStatusRank(scan.status)<targetStatusRank(current.status)||(targetStatusRank(scan.status)===targetStatusRank(current.status)&&activity>(current.activity||'')))projectStatuses.set(scan.project_id,{status:scan.status,activity});
        }
        document.querySelectorAll(`[data-scan-row="${scan.id}"]`).forEach(row=>{const badge=row.querySelector('[data-scan-status]');if(badge){badge.className=`status ${scan.status}`;badge.querySelector('[data-status-text]').textContent=scan.status}const finished=row.querySelector('[data-scan-finished]');if(finished&&scan.finished_at)finished.textContent=scan.finished_at;const action=row.querySelector('[data-scan-action]');if(action){const done=scan.status==='complete';action.href=done?action.dataset.reportUrl:action.dataset.targetUrl;action.textContent=done?'View report →':'Open item →'}});
      });
      projectStatuses.forEach((state,projectId)=>document.querySelectorAll(`[data-project-id="${projectId}"]`).forEach(row=>{row.dataset.status=state.status;row.dataset.activity=state.activity||row.dataset.activity||'';const badge=row.querySelector('[data-project-status]');if(badge){badge.className=`status ${state.status}`;badge.querySelector('[data-status-text]').textContent=state.status}}));
      refreshTargetPanels();
      if(monitor&&data.tracked){const scan=data.tracked,status=monitor.querySelector('[data-status]'),log=monitor.querySelector('[data-log]');status.textContent=scan.status;if(scan.progress){Object.entries(scan.progress.counts||{}).forEach(([key,value])=>{const el=monitor.querySelector(`[data-progress-count="${key}"]`);if(el)el.textContent=value||0});const failures=monitor.querySelector('[data-progress-failures]');if(failures){const rows=scan.progress.failures||[];failures.hidden=!rows.length;failures.replaceChildren(...rows.map(row=>{const el=document.createElement('span');el.textContent=`${row.stage||'stage'} · ${row.tool||'tool'} · ${row.status||'failed'}`;return el}))}}if(scan.log&&log.textContent!==scan.log){log.textContent=scan.log;log.scrollTop=log.scrollHeight}if(['complete','failed','cancelled'].includes(scan.status)){stream.close();setTimeout(()=>location.reload(),500)}}
    });
    window.addEventListener('pagehide',()=>stream.close(),{once:true});
  }

  const tabs=document.querySelectorAll('[data-tab]');
  tabs.forEach(btn=>btn.addEventListener('click',()=>{tabs.forEach(x=>x.classList.toggle('active',x===btn));document.querySelectorAll('[data-pane]').forEach(x=>x.classList.toggle('hidden',x.dataset.pane!==btn.dataset.tab));history.replaceState(null,'',`#${btn.dataset.tab}`)}));
  const initial=location.hash.slice(1),initialTab=document.querySelector(`[data-tab="${CSS.escape(initial)}"]`);if(initialTab)initialTab.click();

  document.querySelectorAll('[data-filter]').forEach(filter=>filter.addEventListener('input',()=>{const list=filter.dataset.filter,q=filter.value.toLowerCase();document.querySelectorAll(`[data-filter-list="${list}"]>.inventory-row,[data-filter-list="${list}"]>.tech-host-card,[data-filter-list="${list}"]>.ip-card`).forEach(x=>x.hidden=!x.textContent.toLowerCase().includes(q))}));
  document.querySelectorAll('.target-panel').forEach(panel=>{
    panel.querySelector('[data-target-search]')?.addEventListener('input',()=>filterTargetPanel(panel));
    panel.querySelector('[data-status-filter]')?.addEventListener('change',()=>filterTargetPanel(panel));
    filterTargetPanel(panel);
  });
  document.querySelectorAll('[data-table-search]').forEach(input=>input.addEventListener('input',()=>{const key=input.dataset.tableSearch,q=input.value.toLowerCase();document.querySelectorAll(`[data-search-list="${key}"]>tr,[data-search-list="${key}"]>.report-card`).forEach(row=>row.hidden=!row.textContent.toLowerCase().includes(q))}));

  const modal=document.querySelector('[data-modal]');
  document.querySelectorAll('[data-open-modal]').forEach(x=>x.addEventListener('click',()=>{modal.hidden=false;modal.querySelector('textarea')?.focus()}));
  document.querySelectorAll('[data-close-modal]').forEach(x=>x.addEventListener('click',()=>modal.hidden=true));
  modal?.addEventListener('click',e=>{if(e.target===modal)modal.hidden=true});
  document.querySelectorAll('.target-form,.rescan').forEach(targetForm=>targetForm.addEventListener('submit',async event=>{
    if(targetForm.dataset.uploading==='done')return;
    const targets=targetForm.querySelector('textarea[name="targets"]'),scope=targetForm.querySelector('[data-scope-input]'),uploadId=targetForm.querySelector('[data-scope-upload-id]'),note=targetForm.querySelector('[data-scope-upload-note]'),button=targetForm.querySelector('button.primary');
    const targetText=(targets?.value||'').trim(),scopeText=(scope?.value||'').trim();
    if(targetForm.classList.contains('target-form')&&!targetText&&!scopeText){event.preventDefault();scope?.setCustomValidity('Enter domains or exact scoped hosts.');scope?.reportValidity();setTimeout(()=>scope?.setCustomValidity(''),0);return}
    if(scopeText.length<=20000)return;
    event.preventDefault();targetForm.dataset.uploading='busy';if(button)button.disabled=true;if(note){note.hidden=false;note.textContent='Preparing large scope list…'}
    try{
      const csrf=targetForm.querySelector('input[name="csrf_token"]')?.value||'',chunkSize=24000;let id='';
      for(let offset=0;offset<scopeText.length;offset+=chunkSize){
        const body=new FormData();body.append('csrf_token',csrf);if(id)body.append('upload_id',id);body.append('chunk',scopeText.slice(offset,offset+chunkSize));
        const response=await fetch('/api/scope-upload',{method:'POST',body});
        if(!response.ok)throw new Error(await response.text()||'Upload failed');
        const data=await response.json();id=data.upload_id;if(note)note.textContent=`Uploaded ${Math.min(scopeText.length,offset+chunkSize).toLocaleString()} of ${scopeText.length.toLocaleString()} characters…`;
      }
      if(uploadId)uploadId.value=id;if(scope)scope.value='';targetForm.dataset.uploading='done';targetForm.requestSubmit();
    }catch(error){
      targetForm.dataset.uploading='';if(button)button.disabled=false;if(note){note.hidden=false;note.textContent='Large scope upload failed. Try a smaller batch.'}console.error(error);
    }
  }));
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&modal)modal.hidden=true});
  document.querySelector('[data-menu]')?.addEventListener('click',()=>document.querySelector('.sidebar')?.classList.toggle('open'));
  document.querySelectorAll('[data-rate]').forEach(x=>x.addEventListener('click',()=>{const input=document.querySelector('input[name="request_rate"]');if(input)input.value=x.dataset.rate}));
  document.querySelectorAll('form[data-confirm]').forEach(form=>form.addEventListener('submit',event=>{if(!window.confirm(form.dataset.confirm))event.preventDefault()}));
  if(modal&&new URLSearchParams(location.search).get('add')==='1'){modal.hidden=false;modal.querySelector('textarea')?.focus()}
});
