use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_512};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use tfhe::prelude::*;
use tfhe::{ClientKey, CompressedServerKey, ConfigBuilder, FheBool, FheUint64};

const MAX_IMPORT_BYTES:usize=256*1024*1024;

fn as_str<'a>(v:&'a Value,key:&str)->Result<&'a str,String>{v.get(key).and_then(Value::as_str).ok_or_else(||format!("missing string field {key}"))}
fn as_u64(v:&Value,key:&str)->Result<u64,String>{v.get(key).and_then(Value::as_u64).ok_or_else(||format!("missing u64 field {key}"))}
fn as_bool(v:&Value,key:&str)->Result<bool,String>{v.get(key).and_then(Value::as_bool).ok_or_else(||format!("missing bool field {key}"))}
fn decode_blob(v:&Value,key:&str)->Result<Vec<u8>,String>{let raw=B64.decode(as_str(v,key)?).map_err(|_|format!("invalid base64 field {key}"))?;if raw.len()>MAX_IMPORT_BYTES{return Err("ciphertext exceeds import size limit".into())}Ok(raw)}

fn load_or_create(key_dir:&PathBuf)->Result<(ClientKey,Vec<u8>,String),Box<dyn std::error::Error>>{
    fs::create_dir_all(key_dir)?;
    let client_path=key_dir.join("client-key.bin");
    let server_path=key_dir.join("server-key.bin");
    let (client,server_bytes)=if client_path.exists() || server_path.exists(){
        if !(client_path.exists() && server_path.exists()){return Err("incomplete TFHE key directory".into())}
        let client:ClientKey=bincode::deserialize(&fs::read(&client_path)?)?;
        let server_bytes=fs::read(&server_path)?;
        let _:CompressedServerKey=bincode::deserialize(&server_bytes)?;
        (client,server_bytes)
    }else{
        let config=ConfigBuilder::default().build();
        let client=ClientKey::generate(config);
        let server=CompressedServerKey::new(&client);
        let client_bytes=bincode::serialize(&client)?;
        let server_bytes=bincode::serialize(&server)?;
        fs::write(&client_path,&client_bytes)?;fs::write(&server_path,&server_bytes)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&client_path,fs::Permissions::from_mode(0o600))?;
            fs::set_permissions(&server_path,fs::Permissions::from_mode(0o644))?;
        }
        (client,server_bytes)
    };
    let key_id=format!("sha3-512:{:x}",Sha3_512::digest(&server_bytes));
    Ok((client,server_bytes,key_id))
}

fn execute(client:&ClientKey,server_bytes:&[u8],key_id:&str,r:&Value)->Result<Value,String>{
    match as_str(r,"op")? {
        "capabilities"=>Ok(json!({"provider":"tfhe","cryptographic":true,"role":"client","has_client_secret":true,"key_id":key_id,"device":"client","supports_server_key_export":true,"tfhe_rs":"1.8.0"})),
        "export_server_key"=>Ok(json!({"data":B64.encode(server_bytes)})),
        "encrypt_bit"=>{let ct=FheBool::try_encrypt(as_bool(r,"value")?,client).map_err(|e|e.to_string())?;Ok(json!({"data":B64.encode(bincode::serialize(&ct).map_err(|e|e.to_string())?)}))},
        "decrypt_bit"=>{let raw=decode_blob(r,"data")?;let ct:FheBool=bincode::deserialize(&raw).map_err(|_|"malformed TFHE bit ciphertext".to_string())?;let value:bool=ct.decrypt(client);Ok(json!({"value":value}))},
        "encrypt_word64"=>{let ct=FheUint64::try_encrypt(as_u64(r,"value")?,client).map_err(|e|e.to_string())?;Ok(json!({"data":B64.encode(bincode::serialize(&ct).map_err(|e|e.to_string())?)}))},
        "decrypt_word64"=>{let raw=decode_blob(r,"data")?;let ct:FheUint64=bincode::deserialize(&raw).map_err(|_|"malformed TFHE word64 ciphertext".to_string())?;let value:u64=ct.decrypt(client);Ok(json!({"value":value}))},
        "close"=>Ok(json!({"closed":true})),
        op=>Err(format!("client sidecar does not permit operation {op}")),
    }
}

fn main()->Result<(),Box<dyn std::error::Error>>{
    let args:Vec<String>=std::env::args().collect();
    let key_dir=PathBuf::from(args.windows(2).find(|w|w[0]=="--key-dir").map(|w|w[1].clone()).unwrap_or_else(||"/keys".into()));
    let (client,server_bytes,key_id)=load_or_create(&key_dir)?;
    let stdin=io::stdin();let mut stdout=io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines(){
        let line=line?;let parsed:Result<Value,_>=serde_json::from_str(&line);
        let op=parsed.as_ref().ok().and_then(|v|v.get("op")).and_then(Value::as_str).unwrap_or("parse").to_string();
        let result=parsed.map_err(|e|e.to_string()).and_then(|r|execute(&client,&server_bytes,&key_id,&r));
        let response=match result{Ok(v)=>json!({"ok":true,"result":v}),Err(e)=>json!({"ok":false,"error":e})};
        serde_json::to_writer(&mut stdout,&response)?;stdout.write_all(b"\n")?;stdout.flush()?;
        if op=="close"{break}
    }
    Ok(())
}
