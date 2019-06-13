// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::{AsRawFd, RawFd};
use std::u32;

use kvm::Datamatch;
use msg_socket::{MsgReceiver, MsgSender};
use resources::{AddressAllocator, Alloc, SystemAllocator};
use sys_util::{error, EventFd};

use vfio_sys::*;
use vm_control::{VfioDeviceRequestSocket, VfioDriverRequest, VfioDriverResponse};

use crate::pci::pci_configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciClassCode, PciConfiguration,
    PciHeaderType, PciSubclass,
};
use crate::pci::pci_device::{Error as PciDeviceError, PciDevice};
use crate::pci::PciInterruptPin;

use crate::vfio::VfioDevice;

#[derive(Copy, Clone)]
enum PciVfioSubclass {
    VfioSubclass = 0xff,
}

impl PciSubclass for PciVfioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Implements the Vfio Pci device, then a pci device is added into vm
pub struct VfioPciDevice {
    device: Box<VfioDevice>,
    config_regs: PciConfiguration,
    pci_bus_dev: Option<(u8, u8)>,
    interrupt_evt: Option<EventFd>,
    interrupt_resample_evt: Option<EventFd>,
    mmio_regions: Vec<(u64, u64, u32)>,
    msi_cap: (u8, u8, bool),
    virq: u32,
    vm_socket: VfioDeviceRequestSocket,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the give Vfio device
    pub fn new(device: Box<VfioDevice>, vfio_device_socket: VfioDeviceRequestSocket) -> Self {
        let config_regs = PciConfiguration::new(
            0,
            0,
            PciClassCode::MultimediaController,
            &PciVfioSubclass::VfioSubclass,
            None,
            PciHeaderType::Device,
            0xABCD,
            0x2468,
        );

        let mut msi_cap: (u8, u8, bool) = (0, 0, false);
        let mut cap_next: u8 = 0;
        // safe as convert u8 to &[u8;1]
        device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            unsafe {
                ::std::slice::from_raw_parts_mut(
                    ::std::mem::transmute::<&mut u8, &mut u8>(&mut cap_next),
                    1,
                )
            },
            0x34,
        );
        while cap_next != 0 {
            let mut cap_id: u8 = 0;
            // safe as convert u8 to &[u8;1]
            device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                unsafe {
                    ::std::slice::from_raw_parts_mut(
                        ::std::mem::transmute::<&mut u8, &mut u8>(&mut cap_id),
                        1,
                    )
                },
                cap_next.into(),
            );
            // find msi cap
            if cap_id == 0x05 {
                let mut msi_len: u8 = 0xa;
                let mut msi_ctl: u16 = 0;
                // safe as convert u16 to &[u8;2]
                device.region_read(
                    VFIO_PCI_CONFIG_REGION_INDEX,
                    unsafe {
                        ::std::slice::from_raw_parts_mut(
                            ::std::mem::transmute::<&mut u16, &mut u8>(&mut msi_ctl),
                            2,
                        )
                    },
                    (cap_next + 2).into(),
                );
                if msi_ctl & 0x80 != 0 {
                    msi_len += 4;
                }
                if msi_ctl & 0x100 != 0 {
                    msi_len += 0xa;
                }
                msi_cap.0 = cap_next;
                msi_cap.1 = msi_len;
                break;
            }
            // safe as convert u8 to &[u8;1]
            device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                unsafe {
                    ::std::slice::from_raw_parts_mut(
                        ::std::mem::transmute::<&mut u8, &mut u8>(&mut cap_next),
                        1,
                    )
                },
                (cap_next + 1).into(),
            );
        }

        VfioPciDevice {
            device,
            config_regs,
            pci_bus_dev: None,
            interrupt_evt: None,
            interrupt_resample_evt: None,
            mmio_regions: Vec::new(),
            msi_cap,
            virq: 0,
            vm_socket: vfio_device_socket,
        }
    }

    fn find_region(&self, addr: u64) -> Option<(u64, u64, u32)> {
        for (start, size, index) in self.mmio_regions.iter() {
            if addr >= *start && addr < *start + *size {
                return Some((*start, *size, *index));
            }
        }

        None
    }

    fn add_msi_routing(&self, gsi: u32, address: u64, data: u32) {
        if let Err(e) = self
            .vm_socket
            .send(&VfioDriverRequest::AddMsiRoute(gsi, address, data))
        {
            error!("failed to send AddMsiRoute request at {:?}", e);
        }
        match self.vm_socket.recv() {
            Ok(VfioDriverResponse::Ok) => return,
            Ok(VfioDriverResponse::Err(e)) => error!("failed to call AddMsiRoute request {:?}", e),
            Err(e) => error!("failed to receive AddMsiRoute response {:?}", e),
        }
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        if self.msi_cap.2 {
            self.device.msi_disable();
        }
        if self.device.unset_dma_map().is_err() {
            error!("failed to remove all guest memory regions from iommu table");
        }
    }
}

impl PciDevice for VfioPciDevice {
    fn debug_label(&self) -> String {
        format!("vfio pci device")
    }

    fn assign_bus_dev(&mut self, bus: u8, device: u8) {
        self.pci_bus_dev = Some((bus, device));
    }

    fn keep_fds(&self) -> Vec<RawFd> {
        let mut fds = self.device.keep_fds();
        if let Some(ref interrupt_evt) = self.interrupt_evt {
            fds.push(interrupt_evt.as_raw_fd());
        }
        if let Some(ref interrupt_resample_evt) = self.interrupt_resample_evt {
            fds.push(interrupt_resample_evt.as_raw_fd());
        }
        fds.push(self.vm_socket.as_raw_fd());
        fds
    }

    fn assign_irq(
        &mut self,
        irq_evt: EventFd,
        _irq_resample_evt: EventFd,
        irq_num: u32,
        irq_pin: PciInterruptPin,
    ) {
        self.config_regs.set_irq(irq_num as u8, irq_pin);
        self.interrupt_evt = Some(irq_evt);
        self.interrupt_resample_evt = None;
        self.virq = irq_num;
    }

    fn need_resample_evt(&self) -> bool {
        false
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>, PciDeviceError> {
        let mut ranges = Vec::new();
        let mut i = VFIO_PCI_BAR0_REGION_INDEX;
        let (bus, dev) = self
            .pci_bus_dev
            .expect("assign_bus_dev must be called prior to allocate_io_bars");

        while i < VFIO_PCI_ROM_REGION_INDEX {
            let mut low_byte: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
            self.device.region_write(
                VFIO_PCI_CONFIG_REGION_INDEX,
                low_byte.as_mut(),
                (0x10 + i * 4) as u64,
            );
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                low_byte.as_mut(),
                (0x10 + i * 4) as u64,
            );

            let mut low = u32::from_le_bytes(low_byte);
            let low_flag = low & 0xf;
            let is_64bit = match low_flag & 0x4 {
                0x4 => true,
                _ => false,
            };
            if low_flag & 0x1 == 0 && low != 0 {
                let mut upper_byte: [u8; 4] = [0, 0, 0, 0];
                if is_64bit {
                    let j = i + 1;
                    upper_byte = [0xff, 0xff, 0xff, 0xff];
                    self.device.region_write(
                        VFIO_PCI_CONFIG_REGION_INDEX,
                        upper_byte.as_mut(),
                        (0x10 + j * 4) as u64,
                    );
                    self.device.region_read(
                        VFIO_PCI_CONFIG_REGION_INDEX,
                        upper_byte.as_mut(),
                        (0x10 + j * 4) as u64,
                    );
                }
                let mut upper = u32::from_le_bytes(upper_byte);
                low &= 0xffff_fff0;
                let mut size: u64 = u64::from(upper);
                size <<= 32;
                size |= u64::from(low);
                let one_bit = size.trailing_zeros();
                size = 2u64.pow(one_bit);
                let allocator: &mut AddressAllocator;
                if size >= 1 << 27 && is_64bit {
                    allocator = resources.device_allocator();
                } else {
                    allocator = resources.mmio_allocator();
                }
                let bar_addr = allocator
                    .allocate(
                        size,
                        Alloc::PciBar {
                            bus,
                            dev,
                            bar: i as u8,
                        },
                        "vfio_bar".to_string(),
                    )
                    .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))?;
                let mut region_type = PciBarRegionType::Memory32BitRegion;
                let mut prefetch = PciBarPrefetchable::NotPrefetchable;
                if is_64bit {
                    region_type = PciBarRegionType::Memory64BitRegion;
                    prefetch = PciBarPrefetchable::Prefetchable;
                }
                let config = PciBarConfiguration::new(i as usize, size, region_type, prefetch);
                self.config_regs
                    .add_pci_bar(&config)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr, e))?;
                ranges.push((bar_addr, size));
                self.mmio_regions.push((bar_addr, size, i));

                low = bar_addr as u32;
                low |= low_flag;
                low_byte = low.to_le_bytes();
                self.device.region_write(
                    VFIO_PCI_CONFIG_REGION_INDEX,
                    low_byte.as_mut(),
                    (0x10 + i * 4) as u64,
                );
                if is_64bit {
                    upper = (bar_addr >> 32) as u32;
                    upper_byte = upper.to_le_bytes();
                    self.device.region_write(
                        VFIO_PCI_CONFIG_REGION_INDEX,
                        upper_byte.as_mut(),
                        (0x10 + (i + 1) * 4) as u64,
                    );
                }
            }

            if is_64bit {
                i += 2;
            } else {
                i += 1;
            }
        }

        if self.device.setup_dma_map().is_err() {
            error!("failed to add all guest memory regions into iommu table");
        }

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        _resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>, PciDeviceError> {
        Ok(Vec::new())
    }

    fn register_device_capabilities(&mut self) -> Result<(), PciDeviceError> {
        Ok(())
    }

    fn ioeventfds(&self) -> Vec<(&EventFd, u64, Datamatch)> {
        Vec::new()
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        let mut config: [u8; 4] = [0, 0, 0, 0];

        self.device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            config.as_mut(),
            (reg_idx * 4) as u64,
        );

        u32::from_le_bytes(config)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        let start = (reg_idx * 4) as u64 + offset;
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, start);

        if start > self.msi_cap.0 as u64
            && start < (self.msi_cap.0 + self.msi_cap.1) as u64
            && data.len() < self.msi_cap.1 as usize
        {
            let was_enabled = self.msi_cap.2;
            let mut msi_ctl: u16 = 0;
            // safe as convert u16 into &[u8;2]
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                unsafe {
                    ::std::slice::from_raw_parts_mut(
                        ::std::mem::transmute::<&mut u16, &mut u8>(&mut msi_ctl),
                        2,
                    )
                },
                (self.msi_cap.0 + 2).into(),
            );
            let mut is_enabled: bool = false;
            if msi_ctl & 0x1 != 0 {
                is_enabled = true;
            }
            if !was_enabled && is_enabled {
                if let Some(ref interrupt_evt) = self.interrupt_evt {
                    self.device.msi_enable(interrupt_evt);

                    // add msi into kvm routing table
                    let mut address: u64 = 0;
                    let mut data: u32 = 0;
                    // 64bit address
                    if msi_ctl & 0x80 != 0 {
                        // safe as convert u64 into &[u8;8]
                        self.device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            unsafe {
                                ::std::slice::from_raw_parts_mut(
                                    ::std::mem::transmute::<&mut u64, &mut u8>(&mut address),
                                    8,
                                )
                            },
                            (self.msi_cap.0 + 4).into(),
                        );
                        // safe as convert u32 into &[u8;4]
                        self.device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            unsafe {
                                ::std::slice::from_raw_parts_mut(
                                    ::std::mem::transmute::<&mut u32, &mut u8>(&mut data),
                                    4,
                                )
                            },
                            (self.msi_cap.0 + 0xC).into(),
                        );
                    } else {
                        // 32 bit address
                        // safe as convert u64 into &[u8;4]
                        self.device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            unsafe {
                                ::std::slice::from_raw_parts_mut(
                                    ::std::mem::transmute::<&mut u64, &mut u8>(&mut address),
                                    4,
                                )
                            },
                            (self.msi_cap.0 + 4).into(),
                        );
                        // safe as convert u32 into &[u8;8]
                        self.device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            unsafe {
                                ::std::slice::from_raw_parts_mut(
                                    ::std::mem::transmute::<&mut u32, &mut u8>(&mut data),
                                    4,
                                )
                            },
                            (self.msi_cap.0 + 8).into(),
                        );
                    }
                    self.add_msi_routing(self.virq, address, data);
                }
            } else if was_enabled && !is_enabled {
                self.device.msi_disable();
            }

            self.msi_cap.2 = is_enabled;
        }
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        if let Some((start, _size, index)) = self.find_region(addr) {
            let offset = addr - start;
            self.device.region_read(index, data, offset);
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        if let Some((start, _size, index)) = self.find_region(addr) {
            let offset = addr - start;
            self.device.region_write(index, data, offset);
        }
    }
}
