//! eBPF map implementations (array and hash) for the userland runtime.
//!
//! Values live in stable storage so the VM can hand out bounds-checked
//! references to them: array maps use one flat allocation, hash maps use a
//! slab of fixed-size boxed values. Deleted hash values are tombstoned (and
//! reusable) but never freed while the map lives, mirroring the kernel's
//! RCU-grace-period semantics — a stale pointer reads recycled memory but is
//! never unsafe.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Array,
    Hash,
}

impl std::fmt::Display for MapKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapKind::Array => write!(f, "array"),
            MapKind::Hash => write!(f, "hash"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapDef {
    pub name: String,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    /// Frozen after creation: stores and update/delete are rejected
    /// (used for `.rodata` global-data maps).
    pub readonly: bool,
    /// Initial contents, copied into the front of the storage at creation
    /// (used for `.data`/`.rodata` global-data maps; rest is zero).
    pub init: Vec<u8>,
}

/// Location of a map value inside its map's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueRef {
    /// Byte offset into the array map's flat storage.
    ArrayElem(u32),
    /// Index into the hash map's value slab.
    Slab(u32),
}

/// A live map instance.
pub struct Map {
    pub def: MapDef,
    storage: Storage,
    /// VM region handle per element (0 = not yet assigned). Indexed by array
    /// element or slab index; lets the VM reuse one region per value.
    pub region_handles: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
enum Storage {
    Array(Vec<u8>),
    Hash {
        index: HashMap<Vec<u8>, u32>,
        slab: Vec<Box<[u8]>>,
        free: Vec<u32>,
    },
}

/// A point-in-time copy of a map's contents *and* its VM region-handle
/// assignments, for the debugger's time travel. Restoring the handles matters:
/// they are allocated lazily in execution order, so replay from a snapshot
/// must resume allocation from exactly the snapshotted state or guest-visible
/// virtual addresses would diverge from the original run.
#[derive(Clone, Debug, PartialEq)]
pub struct MapSnapshot {
    storage: Storage,
    region_handles: Vec<u32>,
}

impl Map {
    pub fn new(def: MapDef) -> Result<Map, String> {
        if def.value_size == 0 || def.max_entries == 0 {
            return Err(format!(
                "map '{}': zero value_size or max_entries",
                def.name
            ));
        }
        let (storage, handles) = match def.kind {
            MapKind::Array => {
                if def.key_size != 4 {
                    return Err(format!("array map '{}' requires key_size=4", def.name));
                }
                let mut data = vec![0u8; def.max_entries as usize * def.value_size as usize];
                if def.init.len() > data.len() {
                    return Err(format!(
                        "map '{}': initial data larger than storage",
                        def.name
                    ));
                }
                data[..def.init.len()].copy_from_slice(&def.init);
                (
                    Storage::Array(data),
                    vec![0u32; def.max_entries as usize],
                )
            }
            MapKind::Hash => {
                if def.key_size == 0 {
                    return Err(format!("hash map '{}': zero key_size", def.name));
                }
                if !def.init.is_empty() {
                    return Err(format!("hash map '{}' cannot have initial data", def.name));
                }
                (
                    Storage::Hash {
                        index: HashMap::new(),
                        slab: Vec::new(),
                        free: Vec::new(),
                    },
                    Vec::new(),
                )
            }
        };
        Ok(Map {
            def,
            storage,
            region_handles: handles,
        })
    }

    pub fn lookup(&self, key: &[u8]) -> Option<ValueRef> {
        if key.len() != self.def.key_size as usize {
            return None;
        }
        match &self.storage {
            Storage::Array(_) => {
                let idx = u32::from_ne_bytes(key.try_into().ok()?);
                (idx < self.def.max_entries).then_some(ValueRef::ArrayElem(idx))
            }
            Storage::Hash { index, .. } => index.get(key).map(|&i| ValueRef::Slab(i)),
        }
    }

    pub fn value(&self, r: ValueRef) -> &[u8] {
        let vs = self.def.value_size as usize;
        match (&self.storage, r) {
            (Storage::Array(data), ValueRef::ArrayElem(i)) => {
                &data[i as usize * vs..(i as usize + 1) * vs]
            }
            (Storage::Hash { slab, .. }, ValueRef::Slab(i)) => &slab[i as usize],
            _ => unreachable!("value ref kind mismatch"),
        }
    }

    pub fn value_mut(&mut self, r: ValueRef) -> &mut [u8] {
        let vs = self.def.value_size as usize;
        match (&mut self.storage, r) {
            (Storage::Array(data), ValueRef::ArrayElem(i)) => {
                &mut data[i as usize * vs..(i as usize + 1) * vs]
            }
            (Storage::Hash { slab, .. }, ValueRef::Slab(i)) => &mut slab[i as usize],
            _ => unreachable!("value ref kind mismatch"),
        }
    }

    /// Insert or overwrite. Existing values are updated in place so
    /// previously handed out references stay valid.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<ValueRef, i64> {
        if self.def.readonly {
            return Err(-1); // EPERM: frozen map
        }
        if key.len() != self.def.key_size as usize || value.len() != self.def.value_size as usize {
            return Err(-22); // EINVAL
        }
        match &mut self.storage {
            Storage::Array(data) => {
                let idx = u32::from_ne_bytes(key.try_into().map_err(|_| -22i64)?);
                if idx >= self.def.max_entries {
                    return Err(-7); // E2BIG
                }
                let vs = self.def.value_size as usize;
                data[idx as usize * vs..(idx as usize + 1) * vs].copy_from_slice(value);
                Ok(ValueRef::ArrayElem(idx))
            }
            Storage::Hash { index, slab, free } => {
                if let Some(&i) = index.get(key) {
                    slab[i as usize].copy_from_slice(value);
                    return Ok(ValueRef::Slab(i));
                }
                if index.len() >= self.def.max_entries as usize {
                    return Err(-7); // E2BIG
                }
                let i = if let Some(i) = free.pop() {
                    slab[i as usize].copy_from_slice(value);
                    i
                } else {
                    slab.push(value.to_vec().into_boxed_slice());
                    self.region_handles.push(0);
                    (slab.len() - 1) as u32
                };
                index.insert(key.to_vec(), i);
                Ok(ValueRef::Slab(i))
            }
        }
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(), i64> {
        if self.def.readonly {
            return Err(-1); // EPERM: frozen map
        }
        match &mut self.storage {
            Storage::Array(_) => Err(-22), // EINVAL: array elements cannot be deleted
            Storage::Hash { index, free, .. } => match index.remove(key) {
                Some(i) => {
                    free.push(i);
                    Ok(())
                }
                None => Err(-2), // ENOENT
            },
        }
    }

    /// Capture contents + region-handle state (see [`MapSnapshot`]).
    pub fn snapshot(&self) -> MapSnapshot {
        MapSnapshot {
            storage: self.storage.clone(),
            region_handles: self.region_handles.clone(),
        }
    }

    /// Restore a snapshot taken from this map.
    pub fn restore(&mut self, s: &MapSnapshot) {
        self.storage = s.storage.clone();
        self.region_handles = s.region_handles.clone();
    }

    /// The key currently mapped to hash slab index `i` (hash maps only),
    /// found by reverse scan. O(n); used by the race explorer to attribute a
    /// value-pointer access back to its `(map, key)` cell.
    pub fn key_for_slab(&self, i: u32) -> Option<Vec<u8>> {
        match &self.storage {
            Storage::Hash { index, .. } => {
                index.iter().find(|(_, &v)| v == i).map(|(k, _)| k.clone())
            }
            _ => None,
        }
    }

    /// Live entries, for dumping from the CLI/debugger.
    pub fn iter_entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        match &self.storage {
            Storage::Array(data) => {
                let vs = self.def.value_size as usize;
                (0..self.def.max_entries)
                    .map(|i| {
                        (
                            i.to_ne_bytes().to_vec(),
                            data[i as usize * vs..(i as usize + 1) * vs].to_vec(),
                        )
                    })
                    .collect()
            }
            Storage::Hash { index, slab, .. } => index
                .iter()
                .map(|(k, &i)| (k.clone(), slab[i as usize].to_vec()))
                .collect(),
        }
    }
}
