use ed25519_dalek::{SigningKey,Signer,VerifyingKey,Signature};
pub type Hash=[u8;32];
pub type Frame=[u8;256];
pub const GENESIS:Hash=[0;32];
fn hash(tag:u8, parts:&[&[u8]])->Hash {let mut h=blake3::Hasher::new();h.update(&[tag]);for p in parts {h.update(p);}*h.finalize().as_bytes()}
fn num(f:&Frame,i:usize)->u64{u64::from_le_bytes(f[i..i+8].try_into().unwrap())}
fn root(f:&Frame)->Hash{hash(3,&[&f[..104],&f[136..192]])}
pub fn mint(k:&SigningKey,seq:u64,start:u64,end:u64,verdict:u32,qow:Hash,prev:Hash,policy:[u8;24])->Frame{
 let mut f=[0;256];f[..8].copy_from_slice(b"QoP_v01\0");f[8..16].copy_from_slice(&seq.to_le_bytes());f[16..24].copy_from_slice(&start.to_le_bytes());f[24..32].copy_from_slice(&end.to_le_bytes());f[32..36].copy_from_slice(&verdict.to_le_bytes());f[40..72].copy_from_slice(&qow);f[72..104].copy_from_slice(&prev);f[136..160].copy_from_slice(&policy);f[160..192].copy_from_slice(k.verifying_key().as_bytes());let r=root(&f);f[104..136].copy_from_slice(&r);let s=k.sign(&f[..192]);f[192..].copy_from_slice(&s.to_bytes());f
}
pub fn verify(f:&Frame,k:&VerifyingKey,policy:&[u8;24])->bool{
 &f[..8]==b"QoP_v01\0" && num(f,16)<=num(f,24) && matches!(u32::from_le_bytes(f[32..36].try_into().unwrap()),1..=3) && f[36..40]==[0;4] && &f[136..160]==policy && &f[160..192]==k.as_bytes() && f[104..136]==root(f) && k.verify_strict(&f[..192],&Signature::from_bytes(f[192..].try_into().unwrap())).is_ok()
}
pub fn json(f:&Frame)->String{
 // Restricted JCS profile: ASCII keys/strings, decimal u64 strings, sorted keys.
 serde_json::json!({"schema":"QoP_v01","process_seq":num(f,8).to_string(),"chronos_start_tick":num(f,16).to_string(),"chronos_end_tick":num(f,24).to_string(),"verdict_code":u32::from_le_bytes(f[32..36].try_into().unwrap()),"flags":u32::from_le_bytes(f[36..40].try_into().unwrap()),"bound_qow_digest":hex::encode(&f[40..72]),"prev_process_root":hex::encode(&f[72..104]),"next_process_root":hex::encode(&f[104..136]),"reserved_meta":hex::encode(&f[136..160]),"signer_pubkey":hex::encode(&f[160..192]),"signature":hex::encode(&f[192..])}).to_string()
}
fn leaf(f:&Frame)->Hash{hash(0,&[f])}
fn parent(a:Hash,b:Hash)->Hash{hash(1,&[&a,&b])}
fn checkpoint(n:usize,peaks:&[Hash])->Hash{let mut h=blake3::Hasher::new();h.update(&[2]);h.update(&(n as u64).to_le_bytes());for p in peaks{h.update(p);}*h.finalize().as_bytes()}
fn mountains(n:usize)->Vec<(usize,usize)>{let mut out=vec![];let mut start=0;for bit in (0..usize::BITS).rev(){let s=1usize<<bit;if n&s!=0{out.push((start,s));start+=s;}}out}
#[derive(Default)]
pub struct Mmr{levels:Vec<Vec<Hash>>}
#[derive(Clone)]
pub struct Proof{pub index:usize,pub count:usize,pub siblings:Vec<Hash>,pub other_peaks:Vec<Hash>}
impl Mmr{
 pub fn len(&self)->usize{self.levels.first().map_or(0,Vec::len)}
 fn push(&mut self,mut h:Hash){let mut level=0;loop{if self.levels.len()==level{self.levels.push(vec![]);}let v=&mut self.levels[level];v.push(h);if v.len()%2!=0{break;}h=parent(v[v.len()-2],h);level+=1;}}
 fn node(&self,start:usize,size:usize)->Hash{self.levels[size.trailing_zeros() as usize][start/size]}
 pub fn root(&self)->Hash{checkpoint(self.len(),&mountains(self.len()).iter().map(|&(s,z)|self.node(s,z)).collect::<Vec<_>>())}
 pub fn proof(&self,index:usize)->Option<Proof>{if index>=self.len(){return None;}let mut siblings=vec![];let mut other_peaks=vec![];for (s,z) in mountains(self.len()){if index>=s && index-s<z{for l in 0..z.trailing_zeros(){let size=1usize<<l;siblings.push(self.node(((index/size)^1)*size,size));}}else{other_peaks.push(self.node(s,z));}}Some(Proof{index,count:self.len(),siblings,other_peaks})}
}
pub fn verify_proof(f:&Frame,p:&Proof,k:&VerifyingKey,policy:&[u8;24],trusted_root:Hash,trusted_count:usize)->bool{
 if !verify(f,k,policy)||p.count!=trusted_count||p.index>=p.count||num(f,8)!=p.index as u64{return false;}
 let mut peaks=vec![];let mut others=p.other_peaks.iter();for(s,z)in mountains(p.count){if p.index>=s&&p.index-s<z{if p.siblings.len()!=z.trailing_zeros() as usize{return false;}let mut h=leaf(f);for(l,b)in p.siblings.iter().enumerate(){h=if (p.index>>l)&1==0{parent(h,*b)}else{parent(*b,h)};}peaks.push(h);}else{match others.next(){Some(h)=>peaks.push(*h),None=>return false}}}others.next().is_none()&&checkpoint(p.count,&peaks)==trusted_root
}
pub struct Ledger{pub mmr:Mmr,prev:Hash,end:u64,key:VerifyingKey,policy:[u8;24]}
impl Ledger{pub fn new(key:VerifyingKey,policy:[u8;24])->Self{Self{mmr:Mmr::default(),prev:GENESIS,end:0,key,policy}}pub fn append(&mut self,f:&Frame)->bool{if !verify(f,&self.key,&self.policy)||num(f,8)!=self.mmr.len() as u64||f[72..104]!=self.prev||num(f,16)<self.end{return false;}self.prev.copy_from_slice(&f[104..136]);self.end=num(f,24);self.mmr.push(leaf(f));true}}
