use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_512};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{set_server_key, CompressedServerKey, FheBool, FheUint64};

const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;
const RC: [u64; 24] = [
    0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
    0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
    0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
    0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
    0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
    0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008,
];
const RHO: [[u32; 5]; 5] = [
    [0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14],
];

#[derive(Clone)]
enum Ct { Bit(FheBool), Word(FheUint64) }

#[derive(Default, Clone, Serialize)]
struct Metric { calls: u64, total_ns: u128, max_ns: u128 }

#[derive(Default, Clone, Serialize)]
struct KeccakTiming {
    rounds_ns: Vec<u128>,
    theta_ns: u128,
    rho_pi_ns: u128,
    chi_ns: u128,
    iota_ns: u128,
}

struct Store {
    next: u64,
    objects: HashMap<String, Ct>,
    metrics: HashMap<String, Metric>,
    selector_cache: HashMap<(String, usize), Arc<[FheBool]>>,
    key_id: String,
    device: String,
}

impl Store {
    fn put(&mut self, value: Ct) -> String {
        self.next += 1;
        let h = format!("h{}", self.next);
        self.objects.insert(h.clone(), value);
        h
    }
    fn bit(&self, h: &str) -> Result<FheBool, String> {
        match self.objects.get(h) { Some(Ct::Bit(v)) => Ok(v.clone()), Some(_) => Err("ciphertext kind mismatch".into()), None => Err("unknown ciphertext handle".into()) }
    }
    fn word(&self, h: &str) -> Result<FheUint64, String> {
        match self.objects.get(h) { Some(Ct::Word(v)) => Ok(v.clone()), Some(_) => Err("ciphertext kind mismatch".into()), None => Err("unknown ciphertext handle".into()) }
    }
    fn record(&mut self, op: &str, elapsed: u128) {
        let m = self.metrics.entry(op.to_string()).or_default();
        m.calls += 1; m.total_ns += elapsed; m.max_ns = m.max_ns.max(elapsed);
    }
    fn resident_serialized_bytes(&self) -> u64 {
        self.objects.values().filter_map(|ct| match ct {
            Ct::Bit(v) => bincode::serialized_size(v).ok(),
            Ct::Word(v) => bincode::serialized_size(v).ok(),
        }).sum()
    }
    fn selectors(&mut self, index_handle: &str, bank_len: usize) -> Result<Arc<[FheBool]>, String> {
        let key=(index_handle.to_string(),bank_len);
        if let Some(existing)=self.selector_cache.get(&key).cloned() {
            self.record("selector_cache_hit",0);
            return Ok(existing);
        }
        self.record("selector_cache_miss",0);
        let index=self.word(index_handle)?;
        let selectors: Arc<[FheBool]>=(1..=bank_len)
            .map(|ordinal|index.eq(ordinal as u64))
            .collect::<Vec<_>>()
            .into();
        self.selector_cache.insert(key,Arc::clone(&selectors));
        Ok(selectors)
    }
}

fn as_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> { v.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing string field {key}")) }
fn as_u64(v: &Value, key: &str) -> Result<u64, String> { v.get(key).and_then(Value::as_u64).ok_or_else(|| format!("missing u64 field {key}")) }
fn as_bool(v: &Value, key: &str) -> Result<bool, String> { v.get(key).and_then(Value::as_bool).ok_or_else(|| format!("missing bool field {key}")) }
fn handles(v: &Value, key: &str) -> Result<Vec<String>, String> {
    let a=v.get(key).and_then(Value::as_array).ok_or_else(|| format!("missing array field {key}"))?;
    a.iter().map(|x| x.as_str().map(str::to_owned).ok_or_else(|| "handle array must contain strings".to_string())).collect()
}

fn ct_commitment(ct: &Ct) -> Result<String, String> {
    let bytes = match ct { Ct::Bit(v) => bincode::serialize(v), Ct::Word(v) => bincode::serialize(v) }.map_err(|e| e.to_string())?;
    let mut h=Sha3_512::new(); h.update(b"XAVI-VOID/TFHE-CIPHERTEXT/v1\0"); h.update(bytes);
    Ok(format!("tfhe:sha3-512:{:x}", h.finalize()))
}

fn secret_rotl(value: &FheUint64, amount: &FheUint64) -> FheUint64 {
    // TFHE-safe barrel selector. The branch is over public candidate positions;
    // the encrypted rotation amount is only consumed by FHE equality/CMUX.
    let mut out = FheUint64::encrypt_trivial(0u64);
    for r in 0u64..64 {
        let select = amount.eq(r);
        let candidate = value.rotate_left(r as u32);
        out = select.if_then_else(&candidate, &out);
    }
    out
}

fn select_word(store: &mut Store, bank: &[String], index_handle: &str) -> Result<FheUint64, String> {
    let selectors=store.selectors(index_handle,bank.len())?;
    let mut out=FheUint64::encrypt_trivial(0u64);
    for (h,sel) in bank.iter().zip(selectors.iter()) {
        let candidate=store.word(h)?; out=sel.if_then_else(&candidate,&out);
    }
    Ok(out)
}
fn select_bit(store: &mut Store, bank: &[String], index_handle: &str) -> Result<FheBool, String> {
    let selectors=store.selectors(index_handle,bank.len())?;
    let mut out=FheBool::encrypt_trivial(false);
    for (h,sel) in bank.iter().zip(selectors.iter()) {
        let candidate=store.bit(h)?; out=sel.if_then_else(&candidate,&out);
    }
    Ok(out)
}
fn write_words(store: &mut Store, bank: &[String], index_handle: &str, value: &FheUint64) -> Result<Vec<String>, String> {
    let selectors=store.selectors(index_handle,bank.len())?;
    let mut next=Vec::with_capacity(bank.len());
    for (h,sel) in bank.iter().zip(selectors.iter()) {
        let current=store.word(h)?; let ct=sel.if_then_else(value,&current); next.push(store.put(Ct::Word(ct)));
    }
    Ok(next)
}
fn write_bits(store: &mut Store, bank: &[String], index_handle: &str, value: &FheBool) -> Result<Vec<String>, String> {
    let selectors=store.selectors(index_handle,bank.len())?;
    let mut next=Vec::with_capacity(bank.len());
    for (h,sel) in bank.iter().zip(selectors.iter()) {
        let current=store.bit(h)?; let ct=sel.if_then_else(value,&current); next.push(store.put(Ct::Bit(ct)));
    }
    Ok(next)
}

fn keccak24(mut a: Vec<FheUint64>) -> Result<(Vec<FheUint64>, KeccakTiming), String> {
    if a.len()!=25 { return Err("keccak24 requires 25 words".into()); }
    let mut timing=KeccakTiming::default();
    for rc in RC {
        let round_started=Instant::now();
        let phase=Instant::now();
        let mut c=Vec::with_capacity(5);
        for x in 0..5 { c.push(&(&(&(&a[x] ^ &a[x+5]) ^ &a[x+10]) ^ &a[x+15]) ^ &a[x+20]); }
        let mut d=Vec::with_capacity(5);
        for x in 0..5 { d.push(&c[(x+4)%5] ^ c[(x+1)%5].clone().rotate_left(1u32)); }
        for x in 0..5 { for y in 0..5 { a[x+5*y] = &a[x+5*y] ^ &d[x]; } }
        timing.theta_ns += phase.elapsed().as_nanos();

        let phase=Instant::now();
        let mut b: Vec<FheUint64>=(0..25).map(|_|FheUint64::encrypt_trivial(0u64)).collect();
        for x in 0..5 { for y in 0..5 { b[y+5*((2*x+3*y)%5)] = a[x+5*y].clone().rotate_left(RHO[x][y]); } }
        timing.rho_pi_ns += phase.elapsed().as_nanos();

        let phase=Instant::now();
        for x in 0..5 { for y in 0..5 {
            a[x+5*y] = &b[x+5*y] ^ ((!&b[(x+1)%5+5*y]) & &b[(x+2)%5+5*y]);
        }}
        timing.chi_ns += phase.elapsed().as_nanos();

        let phase=Instant::now();
        a[0] = &a[0] ^ rc;
        timing.iota_ns += phase.elapsed().as_nanos();
        timing.rounds_ns.push(round_started.elapsed().as_nanos());
    }
    Ok((a,timing))
}

fn execute(store: &mut Store, r: &Value) -> Result<Value, String> {
    let op=as_str(r,"op")?;
    match op {
        "capabilities" => Ok(json!({
            "provider":"tfhe","cryptographic":true,"role":"evaluator","has_client_secret":false,
            "supports_boolean":true,"supports_word64":true,
            "supports_oblivious_select":true,"supports_secret_rotation":true,"key_id":store.key_id,
            "device":store.device,"supports_bulk_registers":true,"supports_keccak24":true,"supports_metrics":true,
            "supports_resident_sessions":true,"tfhe_rs":"1.8.0","ciphertexts_resident":true,"timing_clock":"host-wall-ns"
        })),
        "trivial_bit" => { let h=store.put(Ct::Bit(FheBool::encrypt_trivial(as_bool(r,"value")?))); Ok(json!({"handle":h})) },
        "trivial_word64" => { let h=store.put(Ct::Word(FheUint64::encrypt_trivial(as_u64(r,"value")?))); Ok(json!({"handle":h})) },
        "bit_not" => { let h=store.put(Ct::Bit(!store.bit(as_str(r,"value")?)?)); Ok(json!({"handle":h})) },
        "bit_xor" => { let a=store.bit(as_str(r,"left")?)?; let b=store.bit(as_str(r,"right")?)?; let h=store.put(Ct::Bit(&a ^ &b)); Ok(json!({"handle":h})) },
        "bit_and" => { let a=store.bit(as_str(r,"left")?)?; let b=store.bit(as_str(r,"right")?)?; let h=store.put(Ct::Bit(&a & &b)); Ok(json!({"handle":h})) },
        "bit_or" => { let a=store.bit(as_str(r,"left")?)?; let b=store.bit(as_str(r,"right")?)?; let h=store.put(Ct::Bit(&a | &b)); Ok(json!({"handle":h})) },
        "bit_mux" => { let s=store.bit(as_str(r,"selector")?)?; let t=store.bit(as_str(r,"when_true")?)?; let f=store.bit(as_str(r,"when_false")?)?; let h=store.put(Ct::Bit(s.if_then_else(&t,&f))); Ok(json!({"handle":h})) },
        "word_xor" => { let a=store.word(as_str(r,"left")?)?; let b=store.word(as_str(r,"right")?)?; let h=store.put(Ct::Word(&a ^ &b)); Ok(json!({"handle":h})) },
        "word_and" => { let a=store.word(as_str(r,"left")?)?; let b=store.word(as_str(r,"right")?)?; let h=store.put(Ct::Word(&a & &b)); Ok(json!({"handle":h})) },
        "word_not" => { let h=store.put(Ct::Word(!store.word(as_str(r,"value")?)?)); Ok(json!({"handle":h})) },
        "word_rotl_public" => { let v=store.word(as_str(r,"value")?)?; let h=store.put(Ct::Word(v.rotate_left((as_u64(r,"amount")? & 63) as u32))); Ok(json!({"handle":h})) },
        "word_rotl_secret" => { let v=store.word(as_str(r,"value")?)?; let a=store.word(as_str(r,"amount")?)?; let h=store.put(Ct::Word(secret_rotl(&v,&a))); Ok(json!({"handle":h})) },
        "word_eq" => { let a=store.word(as_str(r,"left")?)?; let b=store.word(as_str(r,"right")?)?; let h=store.put(Ct::Bit(a.eq(&b))); Ok(json!({"handle":h})) },
        "word_mux" => { let s=store.bit(as_str(r,"selector")?)?; let t=store.word(as_str(r,"when_true")?)?; let f=store.word(as_str(r,"when_false")?)?; let h=store.put(Ct::Word(s.if_then_else(&t,&f))); Ok(json!({"handle":h})) },
        "select_register" => { let kind=as_str(r,"kind")?; let bank=handles(r,"bank")?; let index=as_str(r,"index")?.to_string(); let selected=match kind { "bit"=>Ct::Bit(select_bit(store,&bank,&index)?), "word64"=>Ct::Word(select_word(store,&bank,&index)?), _=>return Err("unknown register kind".into()) }; let h=store.put(selected); Ok(json!({"handle":h})) },
        "write_register" => { let kind=as_str(r,"kind")?; let bank=handles(r,"bank")?; let index=as_str(r,"index")?.to_string(); let hs=match kind { "bit"=>{let value=store.bit(as_str(r,"value")?)?;write_bits(store,&bank,&index,&value)?}, "word64"=>{let value=store.word(as_str(r,"value")?)?;write_words(store,&bank,&index,&value)?}, _=>return Err("unknown register kind".into()) }; Ok(json!({"handles":hs})) },
        "keccak24" => { let hs=handles(r,"state")?; let mut s=Vec::with_capacity(25); for h in hs { s.push(store.word(&h)?); } let (out,timing)=keccak24(s)?; for ns in timing.rounds_ns.iter(){store.record("keccak_round",*ns);} store.record("keccak_theta",timing.theta_ns); store.record("keccak_rho_pi",timing.rho_pi_ns); store.record("keccak_chi",timing.chi_ns); store.record("keccak_iota",timing.iota_ns); let hs=out.into_iter().map(|x|store.put(Ct::Word(x))).collect::<Vec<_>>(); Ok(json!({"handles":hs,"timing":timing})) },
        "resident_stats" => Ok(json!({"resident_objects":store.objects.len(),"resident_serialized_bytes":store.resident_serialized_bytes(),"cached_selector_sets":store.selector_cache.len(),"next_handle":store.next,"device":store.device,"key_id":store.key_id})),
        "release_handles" => { let hs=handles(r,"handles")?; let mut released=0usize; for h in hs.iter(){ if store.objects.remove(h).is_some(){released+=1;} } store.selector_cache.retain(|(h,_),_|!hs.contains(h)); Ok(json!({"released":released,"resident_objects":store.objects.len()})) },
        "clear_session" => { let released=store.objects.len(); store.objects.clear(); store.selector_cache.clear(); Ok(json!({"released":released,"resident_objects":0})) },
        "export_ciphertext" => { let h=as_str(r,"handle")?; let ct=store.objects.get(h).ok_or_else(||"unknown ciphertext handle".to_string())?; let bytes=match (as_str(r,"kind")?,ct) { ("bit",Ct::Bit(v))=>bincode::serialize(v), ("word64",Ct::Word(v))=>bincode::serialize(v), _=>return Err("ciphertext kind mismatch".into()) }.map_err(|e|e.to_string())?; Ok(json!({"data":B64.encode(bytes)})) },
        "import_ciphertext" => { let raw=B64.decode(as_str(r,"data")?).map_err(|_|"invalid base64 ciphertext".to_string())?; if raw.len()>MAX_IMPORT_BYTES{return Err("ciphertext exceeds import size limit".into())}; let ct=match as_str(r,"kind")? { "bit"=>Ct::Bit(bincode::deserialize(&raw).map_err(|_|"malformed TFHE bit ciphertext".to_string())?), "word64"=>Ct::Word(bincode::deserialize(&raw).map_err(|_|"malformed TFHE word64 ciphertext".to_string())?), _=>return Err("unknown ciphertext kind".into()) }; let h=store.put(ct); Ok(json!({"handle":h})) },
        "ciphertext_commitment" => { let h=as_str(r,"handle")?; let ct=store.objects.get(h).ok_or_else(||"unknown ciphertext handle".to_string())?; Ok(json!({"commitment":ct_commitment(ct)?})) },
        "metrics" => Ok(json!({"operations":store.metrics,"resident_objects":store.objects.len(),"resident_serialized_bytes":store.resident_serialized_bytes(),"cached_selector_sets":store.selector_cache.len(),"device":store.device,"key_id":store.key_id,"gpu_vram_bytes":null,"gpu_kernel_launches":null,"external_profiler_required":store.device=="cuda"})),
        "reset_metrics" => { store.metrics.clear(); Ok(json!({})) },
        "close" => Ok(json!({"closed":true})),
        _ => Err(format!("unknown op {op}")),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args:Vec<String>=std::env::args().collect();
    let requested=args.windows(2).find(|w|w[0]=="--device").map(|w|w[1].to_lowercase()).unwrap_or_else(||"cpu".into());
    let server_key_path=args.windows(2).find(|w|w[0]=="--server-key").map(|w|w[1].clone()).ok_or("--server-key PATH is required")?;
    let key_bytes=fs::read(&server_key_path)?;
    let csks:CompressedServerKey=bincode::deserialize(&key_bytes)?;
    let key_id=format!("sha3-512:{:x}",Sha3_512::digest(&key_bytes));
    let device=match requested.as_str() {
        "cpu" => { set_server_key(csks.decompress()); "cpu".to_string() },
        "cuda"|"gpu" => {
            #[cfg(feature="cuda")] { set_server_key(csks.decompress_to_gpu()); "cuda".to_string() }
            #[cfg(not(feature="cuda"))] { return Err("CUDA requested but sidecar was not built with --features cuda".into()); }
        },
        _ => return Err(format!("unsupported device {requested}").into()),
    };
    let mut store=Store{next:0,objects:HashMap::new(),metrics:HashMap::new(),selector_cache:HashMap::new(),key_id,device};
    let stdin=io::stdin(); let mut stdout=io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line=line?; let started=Instant::now();
        let parsed:Result<Value,_>=serde_json::from_str(&line);
        let op=parsed.as_ref().ok().and_then(|v|v.get("op")).and_then(Value::as_str).unwrap_or("parse").to_string();
        let result=parsed.map_err(|e|e.to_string()).and_then(|r|execute(&mut store,&r));
        let elapsed=started.elapsed().as_nanos(); store.record(&op,elapsed);
        let response=match result { Ok(v)=>json!({"ok":true,"result":v}), Err(e)=>json!({"ok":false,"error":e}) };
        serde_json::to_writer(&mut stdout,&response)?; stdout.write_all(b"\n")?; stdout.flush()?;
        if op=="close" { break; }
    }
    Ok(())
}
