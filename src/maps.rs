//! eBPF map implementations for the userland runtime.
//!
//! Supported kinds: array/hash families, XDP redirect maps, and ringbuf.
//! Values live in stable storage so the VM can hand out bounds-checked
//! references to them: array maps use one flat allocation, hash maps use a
//! slab of fixed-size boxed values. Deleted hash values are tombstoned (and
//! reusable) but never freed while the map lives, mirroring the kernel's
//! RCU-grace-period semantics — a stale pointer reads recycled memory but is
//! never unsafe. See `docs/specs/map-types.md` for the userland model.

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as LookupMap;
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::HashMap as LookupMap;

/// Number of logical CPUs modelled for per-CPU maps. The VM has a single
/// execution CPU (`get_smp_processor_id` returns 0), so in-program helpers
/// always touch CPU 0's copy; the other slots exist for fidelity/testing. See
/// the spec for the rationale.
pub const NR_CPUS: u32 = 4;

/// Default captured stack depth for STACK_TRACE maps whose ELF omits
/// `value_size` (kernel's `PERF_MAX_STACK_DEPTH`).
pub const PERF_MAX_STACK_DEPTH: u32 = 127;

fn copy_map_value(dst: &mut [u8], src: &[u8], spin_lock_off: Option<u32>, existing: bool) {
    let saved_lock = spin_lock_off.and_then(|off| {
        let off = off as usize;
        existing.then(|| <[u8; 4]>::try_from(&dst[off..off + 4]).unwrap())
    });
    dst.copy_from_slice(src);
    if let Some(off) = spin_lock_off {
        let off = off as usize;
        if let Some(saved) = saved_lock {
            dst[off..off + 4].copy_from_slice(&saved);
        } else {
            dst[off..off + 4].fill(0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Array,
    Hash,
    PerCpuArray,
    PerCpuHash,
    LruHash,
    RingBuf,
    /// Per-CPU array of perf-event output slots (`bpf_perf_event_output`).
    PerfEventArray,
    /// Array of cgroup fd/id values (a lookup map for cgroup-membership
    /// helpers). Modelled as a plain array — see `docs/specs/map-types-2.md`.
    CgroupArray,
    /// Map from a u32 stack-id to a captured stack (`bpf_get_stackid`).
    StackTrace,
    /// Array of program identities used exclusively by `bpf_tail_call`.
    ProgArray,
    /// Array whose values are references to compatible inner maps.
    ArrayOfMaps,
    /// Hash whose values are references to compatible inner maps.
    HashOfMaps,
    /// Device-indexed array used by `bpf_redirect_map`.
    DevMap,
    /// CPU-indexed array used by XDP CPU redirection.
    CpuMap,
    /// Hash variant of a device redirect map.
    DevMapHash,
}

/// Userspace update mode for a map-in-map entry, matching the kernel's
/// `BPF_ANY`, `BPF_NOEXIST`, and `BPF_EXIST` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapUpdateMode {
    Any,
    NoExist,
    Exist,
}

impl MapKind {
    /// Number of per-entry value copies (per-CPU maps: `NR_CPUS`, else 1).
    pub fn per_cpu(self) -> u32 {
        match self {
            MapKind::PerCpuArray | MapKind::PerCpuHash => NR_CPUS,
            _ => 1,
        }
    }
    /// Whether this kind is backed by array (index) storage.
    fn is_arraylike(self) -> bool {
        matches!(
            self,
            MapKind::Array
            | MapKind::PerCpuArray
            | MapKind::CgroupArray
            | MapKind::DevMap
            | MapKind::CpuMap
        )
    }
    /// Whether this kind is backed by hash (slab) storage.
    fn is_hashlike(self) -> bool {
        matches!(
            self,
            MapKind::Hash
            | MapKind::PerCpuHash
            | MapKind::LruHash
            | MapKind::StackTrace
            | MapKind::DevMapHash
        )
    }

    pub(crate) fn is_map_of_maps(self) -> bool {
        matches!(self, MapKind::ArrayOfMaps | MapKind::HashOfMaps)
    }
}

impl core::fmt::Display for MapKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            MapKind::Array => "array",
            MapKind::Hash => "hash",
            MapKind::PerCpuArray => "percpu_array",
            MapKind::PerCpuHash => "percpu_hash",
            MapKind::LruHash => "lru_hash",
            MapKind::RingBuf => "ringbuf",
            MapKind::PerfEventArray => "perf_event_array",
            MapKind::CgroupArray => "cgroup_array",
            MapKind::StackTrace => "stack_trace",
            MapKind::ProgArray => "prog_array",
            MapKind::ArrayOfMaps => "array_of_maps",
            MapKind::HashOfMaps => "hash_of_maps",
            MapKind::DevMap => "devmap",
            MapKind::CpuMap => "cpumap",
            MapKind::DevMapHash => "devmap_hash",
        };
        write!(f, "{s}")
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
    /// Map index used as the kernel inner-map template (map-in-map kinds).
    pub inner_map_idx: Option<u32>,
    /// Static `(slot, map index)` values from BTF `.maps.values[]` relocations.
    pub map_in_map_values: Vec<(u32, u32)>,
    /// Byte offset of a direct `struct bpf_spin_lock` member in the BTF map
    /// value, when declared. Spin helpers accept only this exact field.
    pub spin_lock_off: Option<u32>,
}

/// Override a map capacity by exact name before map instantiation.
#[cfg(feature = "std")]
pub(crate) fn set_max_entries(
    maps: &mut [MapDef],
    name: &str,
    max_entries: u32,
) -> Result<(), String> {
    if max_entries == 0 {
        return Err(format!(
            "map max_entries override for '{name}' must be nonzero"
        ));
    }
    let Some(map) = maps.iter_mut().find(|map| map.name == name) else {
        let available = maps
            .iter()
            .map(|map| map.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "map max_entries override names unknown map '{name}'; available: {}",
            if available.is_empty() {
                "<none>"
            } else {
                &available
            }
        ));
    };
    map.max_entries = max_entries;
    Ok(())
}

/// Location of a map value inside its map's storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueRef {
    /// Value-cell index into the array map's flat storage (already includes
    /// the per-CPU stride: entry `k` CPU 0 is cell `k * per_cpu`).
    ArrayElem(u32),
    /// Index into the hash map's value slab.
    Slab(u32),
}

/// An in-flight ringbuf reservation (a record the program is writing before
/// it submits or discards it).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reservation {
    data: Vec<u8>,
    /// VM region handle minted for this reservation.
    handle: u32,
    /// False once submitted or discarded (use-after-consume is then rejected).
    live: bool,
}

/// A live map instance.
pub struct Map {
    pub def: MapDef,
    storage: Storage,
    /// VM region handle per value cell (0 = not yet assigned). Indexed by array
    /// cell or slab index; lets the VM reuse one region per value.
    pub region_handles: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
enum Storage {
    /// Flat storage of `max_entries * per_cpu` value cells.
    Array(Vec<u8>),
    Hash {
        index: LookupMap<Vec<u8>, u32>,
        /// Each slab entry is `per_cpu * value_size` bytes wide.
        slab: Vec<Box<[u8]>>,
        free: Vec<u32>,
        /// LRU recency tick per slab slot (LRU maps only).
        last_used: Vec<u64>,
        /// Monotonic tick source for LRU recency.
        tick: u64,
    },
    RingBuf {
        capacity: u32,
        reserved: Vec<Reservation>,
        /// Submitted / output records, captured for userspace inspection.
        emitted: Vec<Vec<u8>>,
    },
    /// Perf-event array: no readable values, only captured output records
    /// (`bpf_perf_event_output`). All CPU lanes capture into one list.
    PerfEvent { emitted: Vec<Vec<u8>> },
    ProgArray(Vec<Option<u32>>),
    MapArray(Vec<Option<u32>>),
    MapHash { index: LookupMap<Vec<u8>, u32> },
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
    pub fn new(mut def: MapDef) -> Result<Map, String> {
        if !def.kind.is_map_of_maps()
            && (def.inner_map_idx.is_some() || !def.map_in_map_values.is_empty())
        {
            return Err(format!(
                "map '{}' has map-in-map metadata but is a {} map",
                def.name, def.kind
            ));
        }
        // Tolerant defaults for corpus map kinds whose ELF defs frequently omit
        // sizes / max_entries (libbpf fills these from nr_cpus at load time).
        // See docs/specs/map-types-2.md.
        match def.kind {
            MapKind::PerfEventArray => {
                if def.key_size == 0 {
                    def.key_size = 4;
                }
                if def.value_size == 0 {
                    def.value_size = 4;
                }
                if def.max_entries == 0 {
                    def.max_entries = NR_CPUS;
                }
            }
            MapKind::CgroupArray => {
                if def.key_size == 0 {
                    def.key_size = 4;
                }
                if def.value_size == 0 {
                    def.value_size = 4;
                }
                if def.max_entries == 0 {
                    def.max_entries = 1;
                }
            }
            MapKind::StackTrace => {
                if def.key_size == 0 {
                    def.key_size = 4;
                }
                if def.value_size == 0 {
                    def.value_size = PERF_MAX_STACK_DEPTH * 8;
                }
                if def.max_entries == 0 {
                    def.max_entries = 1024;
                }
            }
            MapKind::ProgArray | MapKind::ArrayOfMaps | MapKind::HashOfMaps => {
                if def.key_size == 0 {
                    def.key_size = 4;
                }
                if def.value_size == 0 {
                    def.value_size = 4;
                }
            }
            _ => {}
        }
        if def.max_entries == 0 {
            return Err(format!("map '{}': zero max_entries", def.name));
        }
        if def.value_size == 0
            && !matches!(
                def.kind,
                MapKind::RingBuf
                    | MapKind::PerfEventArray
                    | MapKind::ProgArray
                    | MapKind::ArrayOfMaps
                    | MapKind::HashOfMaps
            )
        {
            return Err(format!("map '{}': zero value_size", def.name));
        }
        if let Some(off) = def.spin_lock_off {
            if !matches!(def.kind, MapKind::Array | MapKind::Hash)
                || off % 4 != 0
                || off.checked_add(4).is_none_or(|end| end > def.value_size)
            {
                return Err(format!(
                    "map '{}': invalid BTF spin-lock offset {off} for {} value size {}",
                    def.name, def.kind, def.value_size
                ));
            }
        }
        let per_cpu = def.kind.per_cpu() as usize;
        let (storage, handles) = if def.kind == MapKind::ProgArray {
            if def.key_size != 4 || def.value_size != 4 || !def.init.is_empty() {
                return Err(format!(
                    "prog_array map '{}' requires key_size=4, value_size=4, and no byte initializer",
                    def.name
                ));
            }
            (
                Storage::ProgArray(vec![None; def.max_entries as usize]),
                Vec::new(),
            )
        } else if def.kind == MapKind::ArrayOfMaps {
            if def.key_size != 4
                || def.value_size != 4
                || !def.init.is_empty()
                || def.inner_map_idx.is_none()
            {
                return Err(format!(
                    "array_of_maps '{}' requires key_size=4, value_size=4, an inner-map template, and no byte initializer",
                    def.name
                ));
            }
            let mut slots = vec![None; def.max_entries as usize];
            for &(slot, map) in &def.map_in_map_values {
                let dst = slots.get_mut(slot as usize).ok_or_else(|| {
                    format!("array_of_maps '{}' slot {slot} is out of range", def.name)
                })?;
                if dst.replace(map).is_some() {
                    return Err(format!(
                        "array_of_maps '{}' has duplicate slot {slot}",
                        def.name
                    ));
                }
            }
            (Storage::MapArray(slots), Vec::new())
        } else if def.kind == MapKind::HashOfMaps {
            if def.key_size == 0
                || def.value_size != 4
                || !def.init.is_empty()
                || def.inner_map_idx.is_none()
                || (def.key_size != 4 && !def.map_in_map_values.is_empty())
            {
                return Err(format!(
                    "hash_of_maps '{}' requires a nonzero key size, value_size=4, an inner-map template, no byte initializer, and 4-byte keys for static values[] initializers",
                    def.name
                ));
            }
            let mut index = LookupMap::new();
            for &(key, map) in &def.map_in_map_values {
                if index.insert(key.to_ne_bytes().to_vec(), map).is_some() {
                    return Err(format!(
                        "hash_of_maps '{}' has duplicate key {key}",
                        def.name
                    ));
                }
            }
            (Storage::MapHash { index }, Vec::new())
        } else if def.kind.is_arraylike() {
            if def.key_size != 4 {
                return Err(format!("array map '{}' requires key_size=4", def.name));
            }
            let cells = def.max_entries as usize * per_cpu;
            let mut data = vec![0u8; cells * def.value_size as usize];
            if def.init.len() > data.len() {
                return Err(format!(
                    "map '{}': initial data larger than storage",
                    def.name
                ));
            }
            data[..def.init.len()].copy_from_slice(&def.init);
            (Storage::Array(data), vec![0u32; cells])
        } else if def.kind.is_hashlike() {
            if def.key_size == 0 {
                return Err(format!("hash map '{}': zero key_size", def.name));
            }
            if !def.init.is_empty() {
                return Err(format!("hash map '{}' cannot have initial data", def.name));
            }
            (
                Storage::Hash {
                    index: LookupMap::new(),
                    slab: Vec::new(),
                    free: Vec::new(),
                    last_used: Vec::new(),
                    tick: 0,
                },
                Vec::new(),
            )
        } else if def.kind == MapKind::RingBuf {
            // RingBuf: max_entries is the byte capacity (power of two expected;
            // not enforced so odd corpus objects still load).
            if !def.init.is_empty() {
                return Err(format!("ringbuf '{}' cannot have initial data", def.name));
            }
            (
                Storage::RingBuf {
                    capacity: def.max_entries,
                    reserved: Vec::new(),
                    emitted: Vec::new(),
                },
                Vec::new(),
            )
        } else {
            // PerfEventArray: no readable values, only captured output records.
            if !def.init.is_empty() {
                return Err(format!(
                    "perf_event_array '{}' cannot have initial data",
                    def.name
                ));
            }
            (Storage::PerfEvent { emitted: Vec::new() }, Vec::new())
        };
        Ok(Map {
            def,
            storage,
            region_handles: handles,
        })
    }

    fn per_cpu(&self) -> usize {
        self.def.kind.per_cpu() as usize
    }

    pub fn lookup(&self, key: &[u8]) -> Option<ValueRef> {
        if key.len() != self.def.key_size as usize {
            return None;
        }
        match &self.storage {
            Storage::Array(_) => {
                let idx = u32::from_ne_bytes(key.try_into().ok()?);
                (idx < self.def.max_entries)
                    .then(|| ValueRef::ArrayElem(idx * self.def.kind.per_cpu()))
            }
            Storage::Hash { index, .. } => index.get(key).map(|&i| ValueRef::Slab(i)),
            Storage::RingBuf { .. }
            | Storage::PerfEvent { .. }
            | Storage::ProgArray(_)
            | Storage::MapArray(_)
            | Storage::MapHash { .. } => None,
        }
    }

    /// CPU 0's `value_size`-byte slice for a value ref (what the program sees).
    pub fn value(&self, r: ValueRef) -> &[u8] {
        let vs = self.def.value_size as usize;
        match (&self.storage, r) {
            (Storage::Array(data), ValueRef::ArrayElem(i)) => {
                &data[i as usize * vs..i as usize * vs + vs]
            }
            (Storage::Hash { slab, .. }, ValueRef::Slab(i)) => &slab[i as usize][..vs],
            _ => unreachable!("value ref kind mismatch"),
        }
    }

    pub fn value_mut(&mut self, r: ValueRef) -> &mut [u8] {
        let vs = self.def.value_size as usize;
        match (&mut self.storage, r) {
            (Storage::Array(data), ValueRef::ArrayElem(i)) => {
                &mut data[i as usize * vs..i as usize * vs + vs]
            }
            (Storage::Hash { slab, .. }, ValueRef::Slab(i)) => &mut slab[i as usize][..vs],
            _ => unreachable!("value ref kind mismatch"),
        }
    }

    /// A specific CPU's copy of a value (per-CPU maps; test/inspection only —
    /// programs on this VM always see CPU 0). `cpu` must be `< NR_CPUS`.
    pub fn value_cpu(&self, r: ValueRef, cpu: u32) -> &[u8] {
        let vs = self.def.value_size as usize;
        let c = cpu as usize;
        match (&self.storage, r) {
            (Storage::Array(data), ValueRef::ArrayElem(i)) => {
                let cell = i as usize + c;
                &data[cell * vs..cell * vs + vs]
            }
            (Storage::Hash { slab, .. }, ValueRef::Slab(i)) => {
                &slab[i as usize][c * vs..c * vs + vs]
            }
            _ => unreachable!("value ref kind mismatch"),
        }
    }

    /// Insert or overwrite. Existing values are updated in place so
    /// previously handed out references stay valid.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<ValueRef, i64> {
        if self.def.readonly {
            return Err(-1); // EPERM: frozen map
        }
        if matches!(
            self.def.kind,
            MapKind::RingBuf
                | MapKind::PerfEventArray
                | MapKind::ProgArray
                | MapKind::ArrayOfMaps
                | MapKind::HashOfMaps
        ) {
            return Err(-22); // EINVAL: no key/value update path
        }
        if key.len() != self.def.key_size as usize || value.len() != self.def.value_size as usize {
            return Err(-22); // EINVAL
        }
        let per_cpu = self.per_cpu();
        let vs = self.def.value_size as usize;
        let spin_lock_off = self.def.spin_lock_off;
        match &mut self.storage {
            Storage::Array(data) => {
                let idx = u32::from_ne_bytes(key.try_into().map_err(|_| -22i64)?);
                if idx >= self.def.max_entries {
                    return Err(-7); // E2BIG
                }
                // CPU 0's cell.
                let cell = idx as usize * per_cpu;
                copy_map_value(
                    &mut data[cell * vs..cell * vs + vs],
                    value,
                    spin_lock_off,
                    true,
                );
                Ok(ValueRef::ArrayElem(cell as u32))
            }
            Storage::Hash {
                index,
                slab,
                free,
                last_used,
                tick,
            } => {
                if let Some(&i) = index.get(key) {
                    copy_map_value(&mut slab[i as usize][..vs], value, spin_lock_off, true);
                    *tick += 1;
                    last_used[i as usize] = *tick;
                    return Ok(ValueRef::Slab(i));
                }
                let lru = self.def.kind == MapKind::LruHash;
                if index.len() >= self.def.max_entries as usize {
                    if lru {
                        // Evict the least-recently-used live entry and reuse it.
                        let victim = index
                            .iter()
                            .min_by_key(|(_, &i)| last_used[i as usize])
                            .map(|(k, &i)| (k.clone(), i));
                        if let Some((vk, i)) = victim {
                            index.remove(&vk);
                            copy_map_value(
                                &mut slab[i as usize][..vs],
                                value,
                                spin_lock_off,
                                false,
                            );
                            // Zero the other CPUs' copies for a fresh entry.
                            for c in 1..per_cpu {
                                slab[i as usize][c * vs..c * vs + vs].fill(0);
                            }
                            *tick += 1;
                            last_used[i as usize] = *tick;
                            index.insert(key.to_vec(), i);
                            return Ok(ValueRef::Slab(i));
                        }
                        return Err(-7);
                    }
                    return Err(-7); // E2BIG
                }
                let i = if let Some(i) = free.pop() {
                    let e = &mut slab[i as usize];
                    copy_map_value(&mut e[..vs], value, spin_lock_off, false);
                    for c in 1..per_cpu {
                        e[c * vs..c * vs + vs].fill(0);
                    }
                    i
                } else {
                    let mut e = vec![0u8; per_cpu * vs].into_boxed_slice();
                    copy_map_value(&mut e[..vs], value, spin_lock_off, false);
                    slab.push(e);
                    self.region_handles.push(0);
                    last_used.push(0);
                    (slab.len() - 1) as u32
                };
                *tick += 1;
                last_used[i as usize] = *tick;
                index.insert(key.to_vec(), i);
                Ok(ValueRef::Slab(i))
            }
            Storage::RingBuf { .. }
            | Storage::PerfEvent { .. }
            | Storage::ProgArray(_)
            | Storage::MapArray(_)
            | Storage::MapHash { .. } => {
                unreachable!()
            }
        }
    }

    pub fn set_program(&mut self, index: u32, program: u32) -> Result<(), i64> {
        match &mut self.storage {
            Storage::ProgArray(slots) => {
                *slots.get_mut(index as usize).ok_or(-7i64)? = Some(program);
                Ok(())
            }
            _ => Err(-22),
        }
    }

    pub fn program_at(&self, index: u32) -> Option<u32> {
        match &self.storage {
            Storage::ProgArray(slots) => slots.get(index as usize).copied().flatten(),
            _ => None,
        }
    }

    pub(crate) fn set_inner_map(
        &mut self,
        index: u32,
        map: u32,
        mode: MapUpdateMode,
    ) -> Result<(), i64> {
        match &mut self.storage {
            Storage::MapArray(slots) => {
                let slot = slots.get_mut(index as usize).ok_or(-7i64)?;
                match mode {
                    MapUpdateMode::NoExist => return Err(-17), // EEXIST: array keys exist
                    MapUpdateMode::Exist | MapUpdateMode::Any => *slot = Some(map),
                }
                Ok(())
            }
            _ => Err(-22),
        }
    }

    pub fn inner_map_at(&self, index: u32) -> Option<u32> {
        match &self.storage {
            Storage::MapArray(slots) => slots.get(index as usize).copied().flatten(),
            _ => None,
        }
    }

    pub(crate) fn set_inner_map_key(
        &mut self,
        key: &[u8],
        map: u32,
        mode: MapUpdateMode,
    ) -> Result<(), i64> {
        if key.len() != self.def.key_size as usize {
            return Err(-22);
        }
        match &mut self.storage {
            Storage::MapHash { index } => {
                let exists = index.contains_key(key);
                if (mode == MapUpdateMode::NoExist && exists)
                    || (mode == MapUpdateMode::Exist && !exists)
                {
                    return Err(if exists { -17 } else { -2 });
                }
                if !exists && index.len() >= self.def.max_entries as usize {
                    return Err(-7);
                }
                index.insert(key.to_vec(), map);
                Ok(())
            }
            _ => Err(-22),
        }
    }

    pub fn inner_map_by_key(&self, key: &[u8]) -> Option<u32> {
        match &self.storage {
            Storage::MapHash { index } => index.get(key).copied(),
            _ => None,
        }
    }

    pub(crate) fn delete_inner_map_key(&mut self, key: &[u8]) -> Result<(), i64> {
        if key.len() != self.def.key_size as usize {
            return Err(-22);
        }
        match &mut self.storage {
            Storage::MapHash { index } => index.remove(key).map(|_| ()).ok_or(-2),
            _ => Err(-22),
        }
    }

    /// Mark an entry recently used (LRU maps; called by the interpreter after a
    /// successful lookup, since `lookup` itself is `&self`).
    pub fn touch(&mut self, key: &[u8]) {
        if self.def.kind != MapKind::LruHash {
            return;
        }
        if let Storage::Hash {
            index,
            last_used,
            tick,
            ..
        } = &mut self.storage
        {
            if let Some(&i) = index.get(key) {
                *tick += 1;
                last_used[i as usize] = *tick;
            }
        }
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(), i64> {
        if self.def.readonly {
            return Err(-1); // EPERM: frozen map
        }
        match &mut self.storage {
            Storage::Array(_) => Err(-22), // EINVAL: array elements cannot be deleted
            Storage::RingBuf { .. }
            | Storage::PerfEvent { .. }
            | Storage::ProgArray(_)
            | Storage::MapArray(_)
            | Storage::MapHash { .. } => Err(-22),
            Storage::Hash { index, free, .. } => match index.remove(key) {
                Some(i) => {
                    free.push(i);
                    Ok(())
                }
                None => Err(-2), // ENOENT
            },
        }
    }

    // -- ringbuf ------------------------------------------------------------

    /// Byte capacity of a ringbuf map (`None` for non-ringbufs).
    pub fn ringbuf_capacity(&self) -> Option<u32> {
        match &self.storage {
            Storage::RingBuf { capacity, .. } => Some(*capacity),
            _ => None,
        }
    }

    /// Index the next reservation will get (so the VM can mint its region
    /// before recording it).
    pub fn ringbuf_next_res(&self) -> u32 {
        match &self.storage {
            Storage::RingBuf { reserved, .. } => reserved.len() as u32,
            _ => 0,
        }
    }

    /// Record a new `size`-byte zeroed reservation with region `handle`.
    pub fn ringbuf_add_reservation(&mut self, size: u32, handle: u32) -> u32 {
        match &mut self.storage {
            Storage::RingBuf { reserved, .. } => {
                reserved.push(Reservation {
                    data: vec![0u8; size as usize],
                    handle,
                    live: true,
                });
                (reserved.len() - 1) as u32
            }
            _ => unreachable!("ringbuf_add_reservation on non-ringbuf"),
        }
    }

    /// Writable bytes of a live reservation (`None` if consumed/out of range).
    pub fn ringbuf_reservation_mut(&mut self, res: u32) -> Option<&mut [u8]> {
        match &mut self.storage {
            Storage::RingBuf { reserved, .. } => {
                let r = reserved.get_mut(res as usize)?;
                r.live.then_some(&mut r.data[..])
            }
            _ => None,
        }
    }

    /// Consume a reservation: submit (capture its bytes) or discard (drop).
    /// Returns EINVAL if already consumed.
    pub fn ringbuf_consume(&mut self, res: u32, submit: bool) -> Result<(), i64> {
        match &mut self.storage {
            Storage::RingBuf {
                reserved, emitted, ..
            } => {
                let r = reserved.get_mut(res as usize).ok_or(-22i64)?;
                if !r.live {
                    return Err(-22);
                }
                r.live = false;
                if submit {
                    emitted.push(core::mem::take(&mut r.data));
                }
                Ok(())
            }
            _ => Err(-22),
        }
    }

    /// Directly capture a record (the `bpf_ringbuf_output` path).
    pub fn ringbuf_output(&mut self, data: Vec<u8>) -> Result<(), i64> {
        match &mut self.storage {
            Storage::RingBuf { emitted, .. } => {
                emitted.push(data);
                Ok(())
            }
            _ => Err(-22),
        }
    }

    /// Submitted / output records captured so far (ringbuf maps).
    pub fn ringbuf_records(&self) -> &[Vec<u8>] {
        match &self.storage {
            Storage::RingBuf { emitted, .. } => emitted,
            _ => &[],
        }
    }

    // -- perf event array ---------------------------------------------------

    /// `bpf_perf_event_output`: capture `data` as a record on the perf-event
    /// array. `cpu` is the CPU index selected by the helper's `flags`; it must
    /// be `< NR_CPUS` (all lanes capture into one list — see the spec).
    pub fn perf_output(&mut self, cpu: u32, data: Vec<u8>) -> Result<(), i64> {
        if cpu >= NR_CPUS {
            return Err(-22); // EINVAL: no such CPU in our model
        }
        match &mut self.storage {
            Storage::PerfEvent { emitted } => {
                emitted.push(data);
                Ok(())
            }
            _ => Err(-22),
        }
    }

    /// Records emitted so far via `bpf_perf_event_output` (perf-event arrays).
    pub fn perf_records(&self) -> &[Vec<u8>] {
        match &self.storage {
            Storage::PerfEvent { emitted } => emitted,
            _ => &[],
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

    /// Live entries, for dumping from the CLI/debugger. Per-CPU maps report
    /// CPU 0's copy; ringbufs report nothing.
    pub fn iter_entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let vs = self.def.value_size as usize;
        let per_cpu = self.def.kind.per_cpu() as usize;
        match &self.storage {
            Storage::Array(data) => (0..self.def.max_entries)
                .map(|i| {
                    let cell = i as usize * per_cpu;
                    (
                        i.to_ne_bytes().to_vec(),
                        data[cell * vs..cell * vs + vs].to_vec(),
                    )
                })
                .collect(),
            Storage::Hash { index, slab, .. } => index
                .iter()
                .map(|(k, &i)| (k.clone(), slab[i as usize][..vs].to_vec()))
                .collect(),
            Storage::MapArray(slots) => slots
                .iter()
                .enumerate()
                .filter_map(|(index, map)| {
                    map.map(|map| {
                        (
                            (index as u32).to_ne_bytes().to_vec(),
                            map.to_ne_bytes().to_vec(),
                        )
                    })
                })
                .collect(),
            Storage::MapHash { index } => index
                .iter()
                .map(|(key, &map)| (key.clone(), map.to_ne_bytes().to_vec()))
                .collect(),
            Storage::RingBuf { .. } | Storage::PerfEvent { .. } | Storage::ProgArray(_) => Vec::new(),
        }
    }
}
