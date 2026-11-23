use super::*;use super::extension::*;use fs2::FileExt;use std::{fs::{File,OpenOptions},io::{Read,Write,Seek,SeekFrom},path::Path};
fn err(s:&str)->std::io::Error{std::io::Error::new(std::io::ErrorKind::InvalidData,s)}
pub struct Recovery{file:File,ledger:Ledger,poison:bool}
impl Recovery{
pub fn open(path:&Path,key:VerifyingKey,policy:[u8;24],floor:&Checkpoint,id:Hash,witness:&VerifyingKey)->std::io::Result<Self>{
if !floor.verify(id,witness){return Err(err("untrusted floor"))}let mut file=OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;file.try_lock_exclusive()?;let mut bytes=vec![];file.read_to_end(&mut bytes)?;let mut ledger=Ledger::new(key,policy);let mut matched=floor.count==0&&ledger.mmr.root()==floor.root;
for chunk in bytes.chunks_exact(256){if !ledger.append(chunk.try_into().unwrap()){return Err(err("corrupt complete frame"))}if ledger.mmr.len()==floor.count{matched=ledger.mmr.root()==floor.root;}}
if !matched{return Err(err("rollback or fork"))}let complete=bytes.len()/256*256;if complete!=bytes.len(){file.set_len(complete as u64)?;file.sync_all()?;}file.seek(SeekFrom::End(0))?;Ok(Self{file,ledger,poison:false})}
pub fn append(&mut self,f:&Frame)->std::io::Result<()>{if self.poison||!self.ledger.append(f){return Err(err("append rejected"))}self.poison=true;self.file.write_all(f)?;self.file.sync_all()?;self.poison=false;Ok(())}
pub fn mmr(&self)->Option<&Mmr>{if self.poison{None}else{Some(&self.ledger.mmr)}}}
pub const PENDING:&str="PENDING PROOF OF PROCESS — CIH VERIFICATION";
pub const VERIFIED:&str="iNNOVULIS VERIFIED";
#[derive(Clone)]pub struct Evidence{pub role:u8,pub challenge:Hash,pub subject:Hash,pub artifact:Hash,pub physical:bool,pub sig:[u8;64]}
impl Evidence{fn msg(&self)->Hash{hash(20,&[&[self.role],&self.challenge,&self.subject,&self.artifact,&[self.physical as u8]])}pub fn sign(role:u8,challenge:Hash,subject:Hash,artifact:Hash,physical:bool,k:&SigningKey)->Self{let mut e=Self{role,challenge,subject,artifact,physical,sig:[0;64]};e.sig=k.sign(&e.msg()).to_bytes();e}}
pub struct Seal{pub status:&'static str,pub digest:Hash,pub sig:[u8;64]}
pub fn seal(e:&[Evidence],keys:&[VerifyingKey;5],challenge:Hash,subject:Hash,verifier:&SigningKey,production_enabled:bool)->Seal{
let distinct=(0..5).all(|i|keys[i]!=verifier.verifying_key()&&(0..i).all(|j|keys[i]!=keys[j]));
let ok=production_enabled&&distinct&&e.len()==5&&e.iter().enumerate().all(|(i,x)|x.role==i as u8&&x.challenge==challenge&&x.subject==subject&&x.artifact!=[0;32]&&x.physical&&keys[i].verify_strict(&x.msg(),&Signature::from_bytes(&x.sig)).is_ok());
let status=if ok{VERIFIED}else{PENDING};let mut h=blake3::Hasher::new();h.update(b"iReceipt-v03");h.update(&challenge);h.update(&subject);h.update(status.as_bytes());for x in e{h.update(&x.msg());h.update(&x.sig);}let digest=*h.finalize().as_bytes();Seal{status,digest,sig:verifier.sign(&digest).to_bytes()}}
pub fn ptp_bound(offset_ns:i64,delay_ns:u64,asymmetry_bound_ns:u64,stamp_error_ns:u64,max_ns:u64)->bool{offset_ns.unsigned_abs().checked_add(delay_ns/2+delay_ns%2).and_then(|x|x.checked_add(asymmetry_bound_ns)).and_then(|x|x.checked_add(stamp_error_ns)).is_some_and(|x|x<=max_ns)}
