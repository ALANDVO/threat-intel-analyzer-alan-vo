import { useEffect, useState, FormEvent } from "react";
import { api } from "../api/client";
import { Vulnerability } from "../types";
import { useAuth } from "../context/AuthContext";
const blank={id:"",title:"",description:"",severity:"high",cvss_v3_score:0,epss_score:0,is_cisa_kev:false,component:"",version_range:""};
export function VulnerabilitiesView(){
 const {user}=useAuth();const [items,setItems]=useState<Vulnerability[]>([]),[page,setPage]=useState(1),[pages,setPages]=useState(1),[severity,setSeverity]=useState("");
 const [loading,setLoading]=useState(true),[error,setError]=useState(""),[busy,setBusy]=useState(false),[show,setShow]=useState(false),[form,setForm]=useState(blank);
 async function load(){setLoading(true);try{const r=await api.vulnerabilities.list({page,severity});setItems(r.items);setPages(r.total_pages);}catch(e){setError(String(e));}finally{setLoading(false);}}
 useEffect(()=>{void load();},[page,severity]);
 async function save(e:FormEvent){e.preventDefault();setBusy(true);setError("");try{const {component,version_range,...data}=form;await api.vulnerabilities.create({...data,affected_packages:component?[{component,version_range}]:[]});setShow(false);await load();}catch(e){setError(String(e));}finally{setBusy(false);}}
 async function remove(id:string){setBusy(true);setError("");try{await api.vulnerabilities.delete(id);await load();}catch(e){setError(String(e));}finally{setBusy(false);}}
 return <section><h2>Vulnerabilities</h2>{error&&<p role="alert">{error}</p>}<label>Filter severity<select value={severity} onChange={e=>{setSeverity(e.target.value);setPage(1);}}><option value="">All</option>{["critical","high","medium","low"].map(v=><option key={v}>{v}</option>)}</select></label>
 {user&&user.role!=="viewer"&&<button onClick={()=>{setForm(blank);setShow(true);}}>Add Vulnerability</button>}
 {loading?<p>Loading vulnerabilities...</p>:items.length===0?<p>No Vulnerabilities Found</p>:items.map(v=><article key={v.id}><h3>{v.id}</h3><h4>{v.title}</h4><span>{v.severity.toUpperCase()}</span>{v.is_cisa_kev&&<span>KEV</span>}<p>{v.description}</p><p>CVSS: {v.cvss_v3_score}; EPSS: {v.epss_score}</p>{v.affected_packages.map((p,i)=><p key={i}>{p.component} {p.version_range}</p>)}{user?.role==="admin"&&<button disabled={busy} onClick={()=>void remove(v.id)}>Delete {v.id}</button>}</article>)}
 <button disabled={page<=1||loading} onClick={()=>setPage(page-1)}>Previous</button><span>Page {page}</span><button disabled={page>=pages||loading} onClick={()=>setPage(page+1)}>Next</button>
 {show&&<form onSubmit={save}>{(["id","title","description","component","version_range"] as const).map(k=><label key={k}>{k}<input aria-label={k} required value={form[k]} onChange={e=>setForm({...form,[k]:e.target.value})}/></label>)}
 <label>Severity<select value={form.severity} onChange={e=>setForm({...form,severity:e.target.value})}>{["critical","high","medium","low"].map(v=><option key={v}>{v}</option>)}</select></label>
 {(["cvss_v3_score","epss_score"] as const).map(k=><label key={k}>{k}<input type="number" min="0" max={k==="epss_score"?1:10} step="0.01" value={form[k]} onChange={e=>setForm({...form,[k]:Number(e.target.value)})}/></label>)}
 <label><input type="checkbox" checked={form.is_cisa_kev} onChange={e=>setForm({...form,is_cisa_kev:e.target.checked})}/>CISA KEV</label><button disabled={busy} type="submit">Save</button><button type="button" onClick={()=>setShow(false)}>Cancel</button></form>}</section>;
}
