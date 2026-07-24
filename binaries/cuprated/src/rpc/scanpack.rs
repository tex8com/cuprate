//! Persistent, block-oriented wallet scan packs.
//!
//! Scan packs are an optional sidecar. They never modify the canonical
//! blockchain database and contain only the data returned to a wallet during
//! a pruned `/get_blocks.bin` restore scan.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    ops::Bound,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use cuprate_fixed_bytes::ByteArray;
use cuprate_types::{BlockCompleteEntry, PrunedTxBlobEntry, TransactionBlobs, rpc::{BlockOutputIndices, TxOutputIndices}};

const MAGIC: &[u8; 8] = b"MWSPACK1";
const FORMAT_VERSION: u32 = 1;
const MAX_PACK_BLOCKS: usize = 10_000;
const MAX_ITEM_BYTES: usize = 64 * 1024 * 1024;
const MAX_INDICES_PER_TX: usize = 1_000_000;

/// One immutable, height-contiguous wallet scan pack.
#[derive(Debug, Clone)]
pub struct ScanPack {
    pub start_height: u64,
    pub end_height: u64,
    pub blocks: Vec<BlockCompleteEntry>,
    pub output_indices: Vec<BlockOutputIndices>,
}

impl ScanPack {
    pub fn new(
        start_height: u64,
        blocks: Vec<BlockCompleteEntry>,
        output_indices: Vec<BlockOutputIndices>,
    ) -> Result<Self> {
        if blocks.is_empty() || blocks.len() != output_indices.len() || blocks.len() > MAX_PACK_BLOCKS {
            bail!("invalid scan pack dimensions")
        }
        let end_height = start_height
            .checked_add(u64::try_from(blocks.len())?)
            .context("scan pack end height overflow")?;
        Ok(Self { start_height, end_height, blocks, output_indices })
    }

    pub fn slice_from(&self, start_height: u64, max_blocks: usize) -> Option<Self> {
        let offset = usize::try_from(start_height.checked_sub(self.start_height)?).ok()?;
        if offset >= self.blocks.len() { return None; }
        let end = offset.saturating_add(max_blocks).min(self.blocks.len());
        Self::new(start_height, self.blocks[offset..end].to_vec(), self.output_indices[offset..end].to_vec()).ok()
    }
}

/// Thread-safe directory index for immutable scan packs.
#[derive(Debug)]
pub struct ScanPackStore {
    directory: PathBuf,
    packs: RwLock<BTreeMap<u64, PathBuf>>,
}

impl ScanPackStore {
    pub fn open(directory: PathBuf) -> Result<Arc<Self>> {
        fs::create_dir_all(&directory)
            .with_context(|| format!("creating scan pack directory {}", directory.display()))?;
        let store = Arc::new(Self { directory, packs: RwLock::new(BTreeMap::new()) });
        store.refresh()?;
        let removed = store.remove_overlaps()?;
        if removed > 0 {
            eprintln!("[SCANPACK] removed {removed} overlapping cache packs during startup");
        }
        Ok(store)
    }

    pub fn refresh(&self) -> Result<()> {
        let mut index = BTreeMap::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue; };
            let Some(height) = name.strip_prefix("pack-").and_then(|v| v.strip_suffix(".mwsp")) else { continue; };
            if let Ok(height) = height.parse::<u64>() { index.insert(height, path); }
        }
        *self.packs.write().expect("scan pack index lock poisoned") = index;
        Ok(())
    }

    pub fn cache_start_height(&self) -> Option<u64> {
        self.packs.read().expect("scan pack index lock poisoned").first_key_value().map(|(height, _)| *height)
    }

    /// Return the first physical pack boundary strictly after `height`.
    ///
    /// The moving-window builder uses this to make a shortened leading pack
    /// rather than writing across an already cached boundary.
    pub fn next_start_after(&self, height: u64) -> Option<u64> {
        self.packs.read().expect("scan pack index lock poisoned")
            .range((Bound::Excluded(height), Bound::Unbounded))
            .next()
            .map(|(start, _)| *start)
    }

    /// Bound a builder request so it cannot cross an existing pack boundary.
    pub fn builder_block_count(&self, height: u64, end: u64, chunk_blocks: usize) -> usize {
        let mut count = usize::try_from(end.saturating_sub(height))
            .unwrap_or(usize::MAX)
            .min(chunk_blocks);
        if let Some(next_start) = self.next_start_after(height) {
            let gap = usize::try_from(next_start.saturating_sub(height)).unwrap_or(usize::MAX);
            count = count.min(gap);
        }
        count
    }

    pub fn load_covering(&self, height: u64, max_blocks: usize) -> Result<Option<ScanPack>> {
        let path = self.packs.read().expect("scan pack index lock poisoned")
            .range((Bound::Unbounded, Bound::Included(height))).next_back().map(|(_, path)| path.clone());
        let Some(path) = path else { return Ok(None); };
        let pack = read_pack(&path)?;
        Ok(pack.slice_from(height, max_blocks))
    }

    /// Return the end of the physical pack that covers `height`.
    ///
    /// The cache builder must advance over the whole immutable file, not merely
    /// over a client-sized slice. Otherwise a moving cache window leaves tiny
    /// duplicate tail packs whenever the chain tip advances between passes.
    pub fn covering_end(&self, height: u64) -> Result<Option<u64>> {
        let path = self.packs.read().expect("scan pack index lock poisoned")
            .range((Bound::Unbounded, Bound::Included(height))).next_back().map(|(_, path)| path.clone());
        let Some(path) = path else { return Ok(None); };
        let pack = read_pack(&path)?;
        Ok((pack.start_height <= height && height < pack.end_height).then_some(pack.end_height))
    }

    pub fn write(&self, pack: &ScanPack) -> Result<()> {
        let (previous, next_start) = {
            let packs = self.packs.read().expect("scan pack index lock poisoned");
            if packs.contains_key(&pack.start_height) {
                bail!("scan pack already exists at height {}", pack.start_height);
            }
            let previous = packs
                .range((Bound::Unbounded, Bound::Excluded(pack.start_height)))
                .next_back()
                .map(|(_, path)| path.clone());
            let next_start = packs
                .range((Bound::Excluded(pack.start_height), Bound::Unbounded))
                .next()
                .map(|(start, _)| *start);
            (previous, next_start)
        };
        if let Some(path) = previous {
            let previous = read_pack(&path)?;
            if previous.end_height > pack.start_height {
                bail!(
                    "scan pack at {} overlaps preceding pack ending at {}",
                    pack.start_height,
                    previous.end_height
                );
            }
        }
        if let Some(next_start) = next_start {
            if pack.end_height > next_start {
                bail!(
                    "scan pack ending at {} overlaps following pack at {}",
                    pack.end_height,
                    next_start
                );
            }
        }
        let final_path = self.directory.join(format!("pack-{:020}.mwsp", pack.start_height));
        let temporary_path = self.directory.join(format!(".pack-{:020}.tmp", pack.start_height));
        write_pack(&temporary_path, pack)?;
        fs::rename(&temporary_path, &final_path)?;
        self.packs.write().expect("scan pack index lock poisoned").insert(pack.start_height, final_path);
        Ok(())
    }

    /// Remove redundant overlapping packs before RPC handlers can observe the
    /// cache. A cache miss is always safe, so retaining the longest suffix is
    /// preferable to serving a structurally ambiguous sidecar after an older
    /// builder version left overlapping files behind.
    fn remove_overlaps(&self) -> Result<usize> {
        let entries: Vec<_> = self
            .packs
            .read()
            .expect("scan pack index lock poisoned")
            .iter()
            .map(|(start, path)| (*start, path.clone()))
            .collect();
        let mut retained: Vec<(u64, u64, PathBuf)> = Vec::new();
        let mut stale = Vec::new();

        'entries: for (start, path) in entries {
            let pack = read_pack(&path)?;
            loop {
                let Some((_, retained_end, _)) = retained.last() else {
                    retained.push((start, pack.end_height, path));
                    continue 'entries;
                };
                if start >= *retained_end {
                    retained.push((start, pack.end_height, path));
                    continue 'entries;
                }
                if pack.end_height >= *retained_end {
                    let (_, _, stale_path) = retained.pop().expect("checked above");
                    stale.push(stale_path);
                    continue;
                }
                stale.push(path);
                continue 'entries;
            }
        }

        for path in &stale {
            fs::remove_file(path)?;
        }
        if !stale.is_empty() {
            self.refresh()?;
        }
        Ok(stale.len())
    }

    /// Delete immutable packs that start before the retained window.
    pub fn remove_before(&self, height: u64) -> Result<usize> {
        let stale: Vec<_> = self.packs.read().expect("scan pack index lock poisoned")
            .iter().filter_map(|(start, path)| (*start < height).then(|| (*start, path.clone()))).collect();
        let mut removed = 0;
        for (start, path) in stale {
            let pack = read_pack(&path)?;
            if pack.start_height < height {
                fs::remove_file(&path)?;
                self.packs.write().expect("scan pack index lock poisoned").remove(&start);
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn write_u32(writer: &mut impl Write, value: u32) -> io::Result<()> { writer.write_all(&value.to_le_bytes()) }
fn write_u64(writer: &mut impl Write, value: u64) -> io::Result<()> { writer.write_all(&value.to_le_bytes()) }
fn read_u32(reader: &mut impl Read) -> io::Result<u32> { let mut b = [0; 4]; reader.read_exact(&mut b)?; Ok(u32::from_le_bytes(b)) }
fn read_u64(reader: &mut impl Read) -> io::Result<u64> { let mut b = [0; 8]; reader.read_exact(&mut b)?; Ok(u64::from_le_bytes(b)) }
fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<()> { write_u32(writer, u32::try_from(bytes.len())?)?; writer.write_all(bytes)?; Ok(()) }
fn read_bytes(reader: &mut impl Read) -> Result<Vec<u8>> { let len = usize::try_from(read_u32(reader)?)?; if len > MAX_ITEM_BYTES { bail!("scan pack item exceeds limit") }; let mut bytes = vec![0; len]; reader.read_exact(&mut bytes)?; Ok(bytes) }

fn write_pack(path: &Path, pack: &ScanPack) -> Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writer.write_all(MAGIC)?; write_u32(&mut writer, FORMAT_VERSION)?;
    write_u64(&mut writer, pack.start_height)?; write_u64(&mut writer, pack.end_height)?;
    write_u32(&mut writer, u32::try_from(pack.blocks.len())?)?;
    for (block, indices) in pack.blocks.iter().zip(&pack.output_indices) {
        writer.write_all(&[u8::from(block.pruned)])?; write_u64(&mut writer, block.block_weight)?; write_bytes(&mut writer, &block.block)?;
        match &block.txs {
            TransactionBlobs::Pruned(txs) => { writer.write_all(&[1])?; write_u32(&mut writer, u32::try_from(txs.len())?)?; for tx in txs { write_bytes(&mut writer, &tx.blob)?; writer.write_all(tx.prunable_hash.as_ref())?; } }
            TransactionBlobs::Normal(txs) => { writer.write_all(&[0])?; write_u32(&mut writer, u32::try_from(txs.len())?)?; for tx in txs { write_bytes(&mut writer, tx.as_ref())?; } }
            TransactionBlobs::None => { writer.write_all(&[2])?; write_u32(&mut writer, 0)?; }
        }
        write_u32(&mut writer, u32::try_from(indices.indices.len())?)?;
        for tx in &indices.indices { write_u32(&mut writer, u32::try_from(tx.indices.len())?)?; for index in &tx.indices { write_u64(&mut writer, *index)?; } }
    }
    writer.flush()?; writer.get_ref().sync_all()?; Ok(())
}

fn read_pack(path: &Path) -> Result<ScanPack> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut magic = [0; 8]; reader.read_exact(&mut magic)?; if &magic != MAGIC { bail!("invalid scan pack magic") }
    if read_u32(&mut reader)? != FORMAT_VERSION { bail!("unsupported scan pack version") }
    let start_height = read_u64(&mut reader)?; let end_height = read_u64(&mut reader)?;
    let count = usize::try_from(read_u32(&mut reader)?)?; if count == 0 || count > MAX_PACK_BLOCKS { bail!("invalid scan pack block count") }
    if end_height.checked_sub(start_height) != Some(u64::try_from(count)?) { bail!("scan pack height interval mismatch") }
    let mut blocks = Vec::with_capacity(count); let mut output_indices = Vec::with_capacity(count);
    for _ in 0..count {
        let mut pruned = [0; 1]; reader.read_exact(&mut pruned)?; let block_weight = read_u64(&mut reader)?; let block = Bytes::from(read_bytes(&mut reader)?);
        let mut tag = [0; 1]; reader.read_exact(&mut tag)?; let tx_count = usize::try_from(read_u32(&mut reader)?)?;
        let txs = match tag[0] {
            0 => TransactionBlobs::Normal((0..tx_count).map(|_| read_bytes(&mut reader).map(Bytes::from)).collect::<Result<_>>()?),
            1 => TransactionBlobs::Pruned((0..tx_count).map(|_| { let blob = Bytes::from(read_bytes(&mut reader)?); let mut hash = [0; 32]; reader.read_exact(&mut hash)?; Ok(PrunedTxBlobEntry { blob, prunable_hash: ByteArray::from(hash) }) }).collect::<Result<_>>()?),
            2 if tx_count == 0 => TransactionBlobs::None,
            _ => bail!("invalid scan pack transaction tag"),
        };
        let tx_index_count = usize::try_from(read_u32(&mut reader)?)?; if tx_index_count > MAX_PACK_BLOCKS * 100_000 { bail!("scan pack has too many transaction index lists") }
        let mut per_block = Vec::with_capacity(tx_index_count);
        for _ in 0..tx_index_count { let index_count = usize::try_from(read_u32(&mut reader)?)?; if index_count > MAX_INDICES_PER_TX { bail!("scan pack has too many output indices") }; let mut indices = Vec::with_capacity(index_count); for _ in 0..index_count { indices.push(read_u64(&mut reader)?); } per_block.push(TxOutputIndices { indices }); }
        blocks.push(BlockCompleteEntry { pruned: pruned[0] != 0, block, block_weight, txs }); output_indices.push(BlockOutputIndices { indices: per_block });
    }
    ScanPack::new(start_height, blocks, output_indices)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(start_height: u64, count: usize) -> ScanPack {
        ScanPack::new(
            start_height,
            (0..count).map(|_| BlockCompleteEntry::default()).collect(),
            (0..count).map(|_| BlockOutputIndices { indices: vec![] }).collect(),
        ).unwrap()
    }

    #[test]
    fn persists_and_slices_pack() {
        let directory = tempfile::tempdir().unwrap(); let store = ScanPackStore::open(directory.path().to_path_buf()).unwrap();
        let pack = pack(100, 2);
        store.write(&pack).unwrap(); let read = store.load_covering(101, 10).unwrap().unwrap(); assert_eq!(read.start_height, 101); assert_eq!(read.end_height, 102); assert_eq!(read.blocks.len(), 1); assert_eq!(store.covering_end(101).unwrap(), Some(102));
    }

    #[test]
    fn preserves_physical_pack_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let store = ScanPackStore::open(directory.path().to_path_buf()).unwrap();
        store.write(&pack(100, 2)).unwrap();
        store.write(&pack(102, 2)).unwrap();

        assert_eq!(store.next_start_after(100), Some(102));
        assert_eq!(store.next_start_after(102), None);
        assert_eq!(store.builder_block_count(101, 200, 1_000), 1);
        assert!(store.write(&pack(101, 1)).is_err());
        assert!(store.write(&pack(104, 1)).is_ok());
    }

    #[test]
    fn removes_overlapping_packs_left_by_an_older_builder() {
        let directory = tempfile::tempdir().unwrap();
        let older = directory.path().join("pack-00000000000000000100.mwsp");
        let newer = directory.path().join("pack-00000000000000000101.mwsp");
        write_pack(&older, &pack(100, 2)).unwrap();
        write_pack(&newer, &pack(101, 2)).unwrap();

        let store = ScanPackStore::open(directory.path().to_path_buf()).unwrap();
        assert_eq!(store.cache_start_height(), Some(101));
        assert!(!older.exists());
        assert!(newer.exists());
    }
}
