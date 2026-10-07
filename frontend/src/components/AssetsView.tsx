import { useEffect, useState, FormEvent } from "react";
import { api } from "../api/client";
import { Asset } from "../types";
import { useAuth } from "../context/AuthContext";
const blank = {name:"", component:"", version:"", environment:"production", criticality:"tier_2", internet_exposed:false, owner_email:"", tags:[]};
export function AssetsView() {
 const {user} = useAuth();
 const [items,setItems]=useState<Asset[]>([]), [page,setPage]=useState(1), [pages,setPages]=useState(1);
 const [loading,setLoading]=useState(true), [error,setError]=useState(""), [busy,setBusy]=useState(false);
 const [form,setForm]=useState(blank), [editing,setEditing]=useState<string|null>(null), [show,setShow]=useState(false);
 async function load() {setLoading(true);try {const r=await api.assets.list({page});setItems(r.items);setPages(r.total_pages);}catch(e){setError(String(e));}finally{setLoading(false);}}
 useEffect(()=>{void load();},[page]);
 async function save(e:FormEvent){e.preventDefault();setBusy(true);setError("");try{if(editing)await api.assets.update(editing,form);else await api.assets.create(form);setShow(false);await load();}catch(e){setError(String(e));}finally{setBusy(false);}}
 async function remove(id:string){setBusy(true);setError("");try{await api.assets.delete(id);await load();}catch(e){setError(String(e));}finally{setBusy(false);}}
 return <section><h2>Assets</h2>{error&&<p role="alert">{error}</p>}
 {user&&user.role!=="viewer"&&<button onClick={()=>{setForm(blank);setEditing(null);setShow(true);}}>Enrol Asset</button>}
 {loading?<p>Loading assets...</p>:items.length===0?<p>No Assets Found</p>:<table className="data-table"><thead><tr><th>Name</th><th>Component</th><th>Version</th><th>Environment</th><th>Actions</th></tr></thead><tbody>{items.map(a=><tr key={a.id}><td>{a.name}</td><td>{a.component}</td><td>{a.version}</td><td>{a.environment}</td><td>{user&&user.role!=="viewer"&&<button onClick={()=>{setEditing(a.id);setForm({...a,tags:[]});setShow(true);}}>Edit {a.name}</button>}{user?.role==="admin"&&<button disabled={busy} onClick={()=>void remove(a.id)}>Delete {a.name}</button>}</td></tr>)}</tbody></table>}
 <button disabled={page<=1||loading} onClick={()=>setPage(page-1)}>Previous</button><span>Page {page}</span><button disabled={page>=pages||loading} onClick={()=>setPage(page+1)}>Next</button>
 {show&&<form onSubmit={save}><h3>{editing?"Edit Asset":"Enrol Asset"}</h3>{(["name","component","version","owner_email"] as const).map(k=><label key={k}>{k}<input aria-label={k} required type={k==="owner_email"?"email":"text"} value={form[k]} onChange={e=>setForm({...form,[k]:e.target.value})}/></label>)}
 <label>Environment<select value={form.environment} onChange={e=>setForm({...form,environment:e.target.value})}>{["production","staging","internal"].map(v=><option key={v}>{v}</option>)}</select></label>
 <label>Criticality<select value={form.criticality} onChange={e=>setForm({...form,criticality:e.target.value})}>{["tier_1","tier_2","tier_3"].map(v=><option key={v}>{v}</option>)}</select></label>
 <label><input type="checkbox" checked={form.internet_exposed} onChange={e=>setForm({...form,internet_exposed:e.target.checked})}/>Internet exposed</label>
 <button type="submit" disabled={busy}>Save</button><button type="button" onClick={()=>setShow(false)}>Cancel</button></form>}</section>;
}
