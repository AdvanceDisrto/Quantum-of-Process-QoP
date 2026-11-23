use super::*;
use std::{fs::{File,OpenOptions},io::{Read,Write},path::Path};
pub fn decode_json(s:&str)->Option<Frame>{
 let v:serde_json::Value=serde_json::from_str(s).ok()?;let mut f=[0;256];f[..8].copy_from_slice(b"QoP_v01\0");
 for (name,i) in [("process_seq",8),("chronos_start_tick",16),("chronos_end_tick",24)]{f[i..i+8].copy_from_slice(&v[name].as_str()?.parse::<u64>().ok()?.to_le_bytes());}
 for (name,i) in [("verdict_code",32),("flags",36)]{f[i..i+4].copy_from_slice(&u32::try_from(v[name].as_u64()?).ok()?.to_le_bytes());}
 for (name,a,b) in [("bound_qow_digest",40,72),("prev_process_root",72,104),("next_process_root",104,136),("reserved_meta",136,160),("signer_pubkey",160,192),("signature",192,256)]{hex::decode_to_slice(v[name].as_str()?,&mut f[a..b]).ok()?;}
 if json(&f)!=s{return None;}Some(f)
}
pub struct Durable{file:File,ledger:Ledger,poisoned:bool}
impl Durable{
 pub fn open(path:&Path,key:VerifyingKey,policy:[u8;24])->std::io::Result<Self>{let mut file=OpenOptions::new().read(true).append(true).create(true).open(path)?;let mut bytes=vec![];file.read_to_end(&mut bytes)?;let mut ledger=Ledger::new(key,policy);for chunk in bytes.chunks_exact(256){if !ledger.append(chunk.try_into().unwrap()){return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"corrupt history"));}}if bytes.len()%256!=0{return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"torn tail; manual recovery required"));}Ok(Self{file,ledger,poisoned:false})}
 pub fn append(&mut self,f:&Frame)->std::io::Result<()>{if self.poisoned||!self.ledger.append(f){return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"rejected"));}self.poisoned=true;self.file.write_all(f)?;self.file.sync_all()?;self.poisoned=false;Ok(())}
 pub fn state(&self)->Option<(usize,Hash)>{if self.poisoned{None}else{Some((self.ledger.mmr.len(),self.ledger.mmr.root()))}}
}
#[derive(Clone)]pub struct Checkpoint{pub ledger_id:Hash,pub count:usize,pub root:Hash,pub sig:[u8;64]}
impl Checkpoint{fn message(&self)->Hash{hash(4,&[&self.ledger_id,&(self.count as u64).to_le_bytes(),&self.root])}pub fn sign(id:Hash,m:&Mmr,k:&SigningKey)->Self{let mut c=Self{ledger_id:id,count:m.len(),root:m.root(),sig:[0;64]};c.sig=k.sign(&c.message()).to_bytes();c}pub fn verify(&self,id:Hash,k:&VerifyingKey)->bool{self.ledger_id==id&&k.verify_strict(&self.message(),&Signature::from_bytes(&self.sig)).is_ok()}}
pub struct Consistency{pub old_peaks:Vec<Hash>,pub suffix:Vec<Hash>}
fn blocks(mut a:usize,b:usize)->Vec<(usize,usize)>{let mut v=vec![];while a<b{let max=1usize<<(usize::BITS-1-(b-a).leading_zeros());let z=if a==0{max}else{max.min(1usize<<a.trailing_zeros())};v.push((a,z));a+=z;}v}
pub fn consistency(m:&Mmr,old:usize)->Option<Consistency>{if old>m.len(){return None;}Some(Consistency{old_peaks:mountains(old).iter().map(|&(a,z)|m.node(a,z)).collect(),suffix:blocks(old,m.len()).iter().map(|&(a,z)|m.node(a,z)).collect()})}
pub fn verify_consistency(a:&Checkpoint,b:&Checkpoint,p:&Consistency,id:Hash,k:&VerifyingKey)->bool{if !a.verify(id,k)||!b.verify(id,k)||a.count>b.count{return false;}let ms=mountains(a.count);let bs=blocks(a.count,b.count);if ms.len()!=p.old_peaks.len()||bs.len()!=p.suffix.len()||checkpoint(a.count,&p.old_peaks)!=a.root{return false;}let mut stack:Vec<(usize,Hash)>=ms.iter().zip(&p.old_peaks).map(|((_,z),h)|(*z,*h)).collect();for ((_,z),h) in bs.iter().zip(&p.suffix){let(mut size,mut h)=(*z,*h);while stack.last().map(|x|x.0)==Some(size){h=parent(stack.pop().unwrap().1,h);size*=2;}stack.push((size,h));}checkpoint(b.count,&stack.iter().map(|x|x.1).collect::<Vec<_>>())==b.root}
#[derive(Clone)]pub struct Clock{pub node:Hash,pub nonce:u64,pub tick:u64,pub uncertainty:u64,pub sig:[u8;64]}
impl Clock{fn msg(&self)->Hash{hash(5,&[&self.node,&self.nonce.to_le_bytes(),&self.tick.to_le_bytes(),&self.uncertainty.to_le_bytes()])}pub fn sign(node:Hash,nonce:u64,tick:u64,uncertainty:u64,k:&SigningKey)->Self{let mut c=Self{node,nonce,tick,uncertainty,sig:[0;64]};c.sig=k.sign(&c.msg()).to_bytes();c}}
pub fn clock_ok(c:&Clock,node:Hash,nonce:u64,now:u64,max:u64,k:&VerifyingKey)->bool{c.node==node&&c.nonce==nonce&&c.tick.abs_diff(now).checked_add(c.uncertainty).is_some_and(|d|d<=max)&&k.verify_strict(&c.msg(),&Signature::from_bytes(&c.sig)).is_ok()}
pub struct Cih{pub next_epoch:u64,pub energy:VerifyingKey,pub compute:VerifyingKey,pub policy:[u8;24]}
impl Cih{pub fn settle(&mut self,epoch:u64,a:&Frame,b:&Frame,now:u64,skew:u64)->Option<Hash>{if epoch!=self.next_epoch||self.energy==self.compute||!verify(a,&self.energy,&self.policy)||!verify(b,&self.compute,&self.policy)||num(a,8)!=epoch||num(b,8)!=epoch||a[32..36]!=1u32.to_le_bytes()||b[32..36]!=1u32.to_le_bytes()||num(a,24).abs_diff(now)>skew||num(b,24).abs_diff(now)>skew||num(a,24).abs_diff(num(b,24))>skew{return None;}self.next_epoch=self.next_epoch.checked_add(1)?;Some(hash(6,&[&epoch.to_le_bytes(),a,b]))}}
