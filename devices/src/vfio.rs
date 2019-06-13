// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::u32;

use byteorder::{ByteOrder, LittleEndian};
use kvm::{vec_with_array_field, Vm};
use sys_util::{
    error, ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val, warn,
    EventFd, GuestMemory,
};

use vfio_sys::*;

#[derive(Debug)]
pub enum VfioError {
    OpenContainer(io::Error),
    OpenGroup(io::Error),
    GetGroupStatus,
    GroupViable,
    VfioApiVersion,
    VfioType1V2,
    GroupSetContainer,
    ContainerSetIOMMU,
    GroupGetDeviceFD,
    CreateVfioKvmDevice(sys_util::Error),
    KvmSetDeviceAttr,
    VfioDeviceGetInfo,
    VfioDeviceGetRegionInfo,
    InvalidPath,
    IommuDmaMap,
    IommuDmaUnmap,
    VfioDeviceGetIrqInfo,
    VfioDeviceSetIrq,
}

impl fmt::Display for VfioError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VfioError::OpenContainer(e) => write!(f, "failed to open /dev/vfio/vfio container: {}", e),
            VfioError::OpenGroup(e) => write!(f, "failed to open /dev/vfio/$group_num group: {}", e),
            VfioError::GetGroupStatus => write!(f, "failed to get Group Status"),
            VfioError::GroupViable => write!(f, "group is inviable"),
            VfioError::VfioApiVersion => write!(f, "vfio API version doesn't match with VFIO_API_VERSION defined in vfio_sys/srv/vfio.rs"),
            VfioError::VfioType1V2 => write!(f, "container dones't support VfioType1V2 IOMMU driver type"),
            VfioError::GroupSetContainer => write!(f, "failed to add vfio group into vfio container"),
            VfioError::ContainerSetIOMMU => write!(f, "failed to set container's IOMMU driver type as VfioType1V2"),
            VfioError::GroupGetDeviceFD => write!(f, "failed to get vfio device fd"),
            VfioError::CreateVfioKvmDevice(_) => write!(f, "failed to create KVM vfio device"),
            VfioError::KvmSetDeviceAttr => write!(f, "failed to set KVM vfio device's attribute"),
            VfioError::VfioDeviceGetInfo => write!(f, "failed to get vfio device's info or info doesn't match"),
            VfioError::VfioDeviceGetRegionInfo => write!(f, "failed to get vfio device's region info"),
            VfioError::InvalidPath => write!(f,"invalid file path"),
            VfioError::IommuDmaMap => write!(f, "failed to add guest memory map into iommu table"),
            VfioError::IommuDmaUnmap => write!(f, "failed to remove guest memory map from iommu table"),
            VfioError::VfioDeviceGetIrqInfo => write!(f, "failed to get vfio device irq info"),
            VfioError::VfioDeviceSetIrq => write!(f, "failed to set vfio deviece irq"),
        }
    }
}

struct VfioContainer {
    container: File,
}

const VFIO_API_VERSION: u8 = 0;
impl VfioContainer {
    fn new() -> Result<Self, VfioError> {
        let container = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vfio/vfio")
            .map_err(|e| VfioError::OpenContainer(e))?;

        Ok(VfioContainer { container })
    }

    fn get_api_version(&self) -> i32 {
        // Safe as file is vfio container fd and ioctl is defined by kernel.
        unsafe { ioctl(self, VFIO_GET_API_VERSION()) }
    }

    fn check_extension(&self, val: u32) -> bool {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            panic!("IOMMU type error");
        }

        // Safe as file is vfio container and make sure val is valid.
        let ret = unsafe { ioctl_with_val(self, VFIO_CHECK_EXTENSION(), val.into()) };
        ret == 1
    }

    fn set_iommu(&self, val: u32) -> i32 {
        if val != VFIO_TYPE1_IOMMU && val != VFIO_TYPE1v2_IOMMU {
            panic!("IOMMU type error");
        }

        // Safe as file is vfio container and make sure val is valid.
        unsafe { ioctl_with_val(self, VFIO_SET_IOMMU(), val.into()) }
    }

    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<(), VfioError> {
        let dma_map = vfio_iommu_type1_dma_map {
            argsz: mem::size_of::<vfio_iommu_type1_dma_map>() as u32,
            flags: VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            vaddr: user_addr,
            iova,
            size,
        };

        // Safe as file is vfio container, dma_map is constructed by us, and
        // we check the return value
        let ret = unsafe { ioctl_with_ref(self, VFIO_IOMMU_MAP_DMA(), &dma_map) };
        if ret != 0 {
            return Err(VfioError::IommuDmaMap);
        }

        Ok(())
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioError> {
        let mut dma_unmap = vfio_iommu_type1_dma_unmap {
            argsz: mem::size_of::<vfio_iommu_type1_dma_unmap>() as u32,
            flags: 0,
            iova,
            size,
        };

        // Safe as file is vfio container, dma_unmap is constructed by us, and
        // we check the return value
        let ret = unsafe { ioctl_with_mut_ref(self, VFIO_IOMMU_UNMAP_DMA(), &mut dma_unmap) };
        if ret != 0 || dma_unmap.size != size {
            return Err(VfioError::IommuDmaUnmap);
        }

        Ok(())
    }
}

impl AsRawFd for VfioContainer {
    fn as_raw_fd(&self) -> RawFd {
        self.container.as_raw_fd()
    }
}

struct VfioGroup {
    group: File,
    kvm_dev: File,
    container: VfioContainer,
}

impl VfioGroup {
    fn new(id: u32, vm: &Vm) -> Result<Self, VfioError> {
        let mut group_path = String::from("/dev/vfio/");
        let s_id = &id;
        group_path.push_str(s_id.to_string().as_str());

        let group_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(&group_path))
            .map_err(|e| VfioError::OpenGroup(e))?;

        let mut group_status = vfio_group_status {
            argsz: mem::size_of::<vfio_group_status>() as u32,
            flags: 0,
        };
        // Safe as we are the owner of group_file and group_status which are valid value.
        let mut ret =
            unsafe { ioctl_with_mut_ref(&group_file, VFIO_GROUP_GET_STATUS(), &mut group_status) };
        if ret < 0 {
            return Err(VfioError::GetGroupStatus);
        }

        if group_status.flags != VFIO_GROUP_FLAGS_VIABLE {
            return Err(VfioError::GroupViable);
        }

        let container = VfioContainer::new()?;
        if container.get_api_version() as u8 != VFIO_API_VERSION {
            return Err(VfioError::VfioApiVersion);
        }
        if !container.check_extension(VFIO_TYPE1v2_IOMMU) {
            return Err(VfioError::VfioType1V2);
        }

        // Safe as we are the owner of group_file and container_raw_fd which are valid value,
        // and we verify the ret value
        let container_raw_fd = container.as_raw_fd();
        ret = unsafe { ioctl_with_ref(&group_file, VFIO_GROUP_SET_CONTAINER(), &container_raw_fd) };
        if ret < 0 {
            return Err(VfioError::GroupSetContainer);
        }

        ret = container.set_iommu(VFIO_TYPE1v2_IOMMU);
        if ret < 0 {
            return Err(VfioError::ContainerSetIOMMU);
        }

        let kvm_dev = Self::kvm_device_add_group(vm, &group_file)?;

        Ok(VfioGroup {
            group: group_file,
            kvm_dev,
            container,
        })
    }

    fn kvm_device_add_group(vm: &Vm, group: &File) -> Result<File, VfioError> {
        let mut vfio_dev = kvm_sys::kvm_create_device {
            type_: kvm_sys::kvm_device_type_KVM_DEV_TYPE_VFIO,
            fd: 0,
            flags: 0,
        };
        vm.create_device(&mut vfio_dev)
            .map_err(|e| VfioError::CreateVfioKvmDevice(e))?;

        // Safe as we are the owner of vfio_dev.fd which is valid value.
        let vfio_dev_fd = unsafe { File::from_raw_fd(vfio_dev.fd as i32) };

        let group_fd = group.as_raw_fd();
        let group_fd_ptr = &group_fd as *const i32;
        let vfio_dev_attr = kvm_sys::kvm_device_attr {
            flags: 0,
            group: kvm_sys::KVM_DEV_VFIO_GROUP,
            attr: kvm_sys::KVM_DEV_VFIO_GROUP_ADD as u64,
            addr: group_fd_ptr as u64,
        };

        // Safe as we are the owner of vfio_dev_fd and vfio_dev_attr which are valid value,
        // and we verify the return value.
        if 0 != unsafe {
            ioctl_with_ref(&vfio_dev_fd, kvm_sys::KVM_SET_DEVICE_ATTR(), &vfio_dev_attr)
        } {
            return Err(VfioError::KvmSetDeviceAttr);
        }

        Ok(vfio_dev_fd)
    }

    fn kvm_device_del_group(&self) {
        let group_fd = self.as_raw_fd();
        let group_fd_ptr = &group_fd as *const i32;
        let vfio_dev_attr = kvm_sys::kvm_device_attr {
            flags: 0,
            group: kvm_sys::KVM_DEV_VFIO_GROUP,
            attr: kvm_sys::KVM_DEV_VFIO_GROUP_DEL as u64,
            addr: group_fd_ptr as u64,
        };

        // Safe as we are the owner of kvm_dev and vfio_dev_attr which are valid value.
        if 0 != unsafe {
            ioctl_with_ref(
                &self.kvm_dev,
                kvm_sys::KVM_SET_DEVICE_ATTR(),
                &vfio_dev_attr,
            )
        } {
            error!("Failed to remove group from kvm VFIO device");
        }
    }

    fn unset_container(&self) {
        let container_raw_fd = self.container.as_raw_fd();

        // Safe as we are the owner of self and container_raw_fd which are valid value.
        let ret = unsafe { ioctl_with_ref(self, VFIO_GROUP_UNSET_CONTAINER(), &container_raw_fd) };
        if ret < 0 {
            error!("Failed to unset container for group");
        }
    }

    fn get_device(&self, name: &Path) -> Result<File, VfioError> {
        let uuid_osstr = name.file_name().ok_or(VfioError::InvalidPath)?;
        let uuid_str = uuid_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let path: CString = CString::new(uuid_str.as_bytes()).expect("CString::new() failed");
        let path_ptr = path.as_ptr();

        // Safe as we are the owner of self and path_ptr which are valid value.
        let ret = unsafe { ioctl_with_ptr(self, VFIO_GROUP_GET_DEVICE_FD(), path_ptr) };
        if ret < 0 {
            return Err(VfioError::GroupGetDeviceFD);
        }

        // Safe as ret is valid FD
        Ok(unsafe { File::from_raw_fd(ret) })
    }
}

impl AsRawFd for VfioGroup {
    fn as_raw_fd(&self) -> RawFd {
        self.group.as_raw_fd()
    }
}

impl Drop for VfioGroup {
    fn drop(&mut self) {
        self.kvm_device_del_group();
        self.unset_container();
    }
}

struct VfioRegion {
    flags: u32,
    size: u64,
    offset: u64,
}

/// Vfio device for exposing regions which could be read/write to kernel vfio device.
pub struct VfioDevice {
    dev: File,
    group: VfioGroup,
    regions: Vec<VfioRegion>,
    guest_mem: GuestMemory,
}

impl VfioDevice {
    /// Create a new vfio device, then guest read/write on this device could be
    /// transfered into kernel vfio.
    /// sysfspath specify the vfio device path in sys file system.
    pub fn new(sysfspath: &Path, vm: &Vm, guest_mem: GuestMemory) -> Result<Self, VfioError> {
        let mut uuid_path = PathBuf::new();
        uuid_path.push(sysfspath);
        uuid_path.push("iommu_group");
        let group_path = uuid_path.read_link().map_err(|_| VfioError::InvalidPath)?;
        let group_osstr = group_path.file_name().ok_or(VfioError::InvalidPath)?;
        let group_str = group_osstr.to_str().ok_or(VfioError::InvalidPath)?;
        let group_id = group_str
            .parse::<u32>()
            .map_err(|_| VfioError::InvalidPath)?;

        let group = VfioGroup::new(group_id, vm)?;
        let new_dev = group.get_device(sysfspath)?;
        let dev_regions = Self::get_regions(&new_dev)?;

        Ok(VfioDevice {
            dev: new_dev,
            group,
            regions: dev_regions,
            guest_mem,
        })
    }

    /* Only support MSI with eventfd
    fn get_irq_info(&self, count :&mut u32) -> Result<u32, VfioError>{
        let mut irq_info = vfio_irq_info {
                argsz: mem::size_of::<vfio_irq_info>() as u32,
                flags: 0,
                index: VFIO_PCI_MSI_IRQ_INDEX,
                count: 0,
        };
        let ret = unsafe {
            ioctl_with_mut_ref(self, VFIO_DEVICE_GET_IRQ_INFO(), &mut irq_info) };
        if ret < 0 || irq_info.flags & VFIO_IRQ_INFO_EVENTFD == 0 {
            return Err(VfioError::VfioDeviceGetIrqInfo)
        }

        *count = irq_info.count;

        return Ok(irq_info.count)
    } */

    /// enable vfio device's MSI and associate EventFd with this MSI
    pub fn msi_enable(&self, fd: &EventFd) {
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(1);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32 + 4;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = VFIO_PCI_MSI_IRQ_INDEX;
        irq_set[0].start = 0;
        irq_set[0].count = 1;

        {
            // irq_set.data could be none, bool or fd according to flags, so irq_set.data
            // is u8 default, here irq_set.data is fd as u32, so 4 default u8 are combined
            // together as u32. It is safe as enough space is reserved through
            // vec_with_array_field(u32)<1>.
            let fds = unsafe { irq_set[0].data.as_mut_slice(4) };
            LittleEndian::write_u32(fds, fd.as_raw_fd() as u32);
        }

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            error!("Vfio device enable MSI error");
        }
    }

    pub fn msi_disable(&self) {
        let mut irq_set = vec_with_array_field::<vfio_irq_set, u32>(0);
        irq_set[0].argsz = mem::size_of::<vfio_irq_set>() as u32;
        irq_set[0].flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
        irq_set[0].index = VFIO_PCI_MSI_IRQ_INDEX;
        irq_set[0].start = 0;
        irq_set[0].count = 0;

        // Safe as we are the owner of self and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, VFIO_DEVICE_SET_IRQS(), &irq_set[0]) };
        if ret < 0 {
            error!("Vfio device disable MSI error");
        }
    }

    fn get_regions(dev: &File) -> Result<Vec<VfioRegion>, VfioError> {
        let mut regions: Vec<VfioRegion> = Vec::new();
        let mut dev_info = vfio_device_info {
            argsz: mem::size_of::<vfio_device_info>() as u32,
            flags: 0,
            num_regions: 0,
            num_irqs: 0,
        };
        // Safe as we are the owner of dev and dev_info which are valid value,
        // and we verify the return value.
        let ret = unsafe { ioctl_with_mut_ref(dev, VFIO_DEVICE_GET_INFO(), &mut dev_info) };
        if ret < 0
            || (dev_info.flags & VFIO_DEVICE_FLAGS_PCI) == 0
            || dev_info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX + 1
            || dev_info.num_irqs < VFIO_PCI_MSIX_IRQ_INDEX + 1
        {
            return Err(VfioError::VfioDeviceGetInfo);
        }

        for i in VFIO_PCI_BAR0_REGION_INDEX..dev_info.num_regions {
            let mut reg_info = vfio_region_info {
                argsz: mem::size_of::<vfio_region_info>() as u32,
                flags: 0,
                index: i,
                cap_offset: 0,
                size: 0,
                offset: 0,
            };
            // Safe as we are the owner of dev and reg_info which are valid value,
            // and we verify the return value.
            let ret =
                unsafe { ioctl_with_mut_ref(dev, VFIO_DEVICE_GET_REGION_INFO(), &mut reg_info) };
            if ret < 0 {
                return Err(VfioError::VfioDeviceGetRegionInfo);
            }

            let region = VfioRegion {
                flags: reg_info.flags,
                size: reg_info.size,
                offset: reg_info.offset,
            };
            regions.push(region);
        }

        Ok(regions)
    }

    /// Read region's data from VFIO device into buf
    /// index: region num
    /// buf: data destination and buf length is read size
    /// addr: offset in the region
    pub fn region_read(&self, index: u32, buf: &mut [u8], addr: u64) {
        let stub: &VfioRegion;
        match self.regions.get(index as usize) {
            Some(v) => stub = v,
            None => {
                warn!("region read with invalid index: {}", index);
                return;
            }
        }

        let size = buf.len() as u64;
        if size > stub.size || addr + size > stub.size {
            warn!(
                "region read with invalid parameter, add: {}, size: {}",
                addr, size
            );
            return;
        }

        if let Err(e) = self.dev.read_exact_at(buf, stub.offset + addr) {
            warn!(
                "Failed to read region in index: {}, addr: {}, error: {}",
                index, addr, e
            );
        }
    }

    /// write the data from buf into a vfio device region
    /// index: region num
    /// buf: data src and buf length is write size
    /// addr: offset in the region
    pub fn region_write(&self, index: u32, buf: &[u8], addr: u64) {
        let stub: &VfioRegion;
        match self.regions.get(index as usize) {
            Some(v) => stub = v,
            None => {
                warn!("region write with invalid index: {}", index);
                return;
            }
        }

        let size = buf.len() as u64;
        if size > stub.size
            || addr + size > stub.size
            || (stub.flags & VFIO_REGION_INFO_FLAG_WRITE) == 0
        {
            warn!(
                "region write with invalid parameter, add: {}, size: {}",
                addr, size
            );
            return;
        }

        if let Err(e) = self.dev.write_all_at(buf, stub.offset + addr) {
            warn!(
                "Failed to write region in index: {}, addr: {}, error: {}",
                index, addr, e
            );
        }
    }

    /// get vfio device's fds which are passed into minijail process
    pub fn keep_fds(&self) -> Vec<RawFd> {
        let mut fds = Vec::new();
        fds.push(self.as_raw_fd());
        fds.push(self.group.as_raw_fd());
        fds.push(self.group.container.as_raw_fd());
        fds
    }

    fn vfio_dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<(), VfioError> {
        self.group.container.vfio_dma_map(iova, size, user_addr)
    }

    fn vfio_dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioError> {
        self.group.container.vfio_dma_unmap(iova, size)
    }

    /// Add all guest memory regions into vfio container's iommu table,
    /// then vfio kernel driver could access guest memory from gfn
    pub fn setup_dma_map(&self) -> Result<(), VfioError> {
        self.guest_mem
            .with_regions(|_index, guest_addr, size, host_addr, _fd_offset| {
                self.vfio_dma_map(guest_addr.0, size as u64, host_addr as u64)
            })?;
        Ok(())
    }

    /// remove all guest memory regions from vfio containers iommu table
    /// then vfio kernel driver couldn't access this guest memory
    pub fn unset_dma_map(&self) -> Result<(), VfioError> {
        self.guest_mem
            .with_regions(|_index, guest_addr, size, _host_addr, _fd_offset| {
                self.vfio_dma_unmap(guest_addr.0, size as u64)
            })?;
        Ok(())
    }
}

impl AsRawFd for VfioDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }
}
