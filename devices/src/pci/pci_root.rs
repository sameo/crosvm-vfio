// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use sync::Mutex;

use crate::pci::pci_configuration::{
    PciBridgeSubclass, PciClassCode, PciConfiguration, PciHeaderType,
};
use crate::pci::pci_device::PciDevice;
use crate::BusDevice;

// A PciDevice that holds the root hub's configuration.
struct PciRootConfiguration {
    config: PciConfiguration,
}

impl PciDevice for PciRootConfiguration {
    fn debug_label(&self) -> String {
        "pci root device".to_owned()
    }
    fn keep_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        (&mut self.config).write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}
}

/// Emulates the PCI Root bridge.
pub struct PciRoot {
    /// Bus configuration for the root device.
    root_configuration: PciRootConfiguration,
    /// Devices attached to this bridge.
    devices: Vec<Arc<Mutex<dyn BusDevice>>>,
}

const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
const PCI_DEVICE_ID_INTEL_82441: u16 = 0x1237;

impl PciRoot {
    /// Create an empty PCI root bus.
    pub fn new() -> Self {
        PciRoot {
            root_configuration: PciRootConfiguration {
                config: PciConfiguration::new(
                    PCI_VENDOR_ID_INTEL,
                    PCI_DEVICE_ID_INTEL_82441,
                    PciClassCode::BridgeDevice,
                    &PciBridgeSubclass::HostBridge,
                    None,
                    PciHeaderType::Bridge,
                    0,
                    0,
                ),
            },
            devices: Vec::new(),
        }
    }

    /// Add a `device` to this root PCI bus.
    pub fn add_device(&mut self, device: Arc<Mutex<dyn BusDevice>>) {
        self.devices.push(device);
    }

    pub fn config_space_read(
        &self,
        bus: usize,
        device: usize,
        _function: usize,
        register: usize,
    ) -> u32 {
        // Only support one bus.
        if bus != 0 {
            return 0xffff_ffff;
        }

        match device {
            0 => {
                // If bus and device are both zero, then read from the root config.
                self.root_configuration.config_register_read(register)
            }
            dev_num => self
                .devices
                .get(dev_num - 1)
                .map_or(0xffff_ffff, |d| d.lock().config_register_read(register)),
        }
    }

    pub fn config_space_write(
        &mut self,
        bus: usize,
        device: usize,
        _function: usize,
        register: usize,
        offset: u64,
        data: &[u8],
    ) {
        if offset as usize + data.len() > 4 {
            return;
        }

        // Only support one bus.
        if bus != 0 {
            return;
        }

        match device {
            0 => {
                // If bus and device are both zero, then read from the root config.
                self.root_configuration
                    .config_register_write(register, offset, data);
            }
            dev_num => {
                // dev_num is 1-indexed here.
                if let Some(d) = self.devices.get(dev_num - 1) {
                    d.lock().config_register_write(register, offset, data);
                }
            }
        }
    }
}

/// Emulates PCI configuration access mechanism #1 (I/O ports 0xcf8 and 0xcfc).
pub struct PciConfigIo {
    /// PCI root bridge.
    pci_root: PciRoot,
    /// Current address to read/write from (0xcf8 register, litte endian).
    config_address: u32,
}

impl PciConfigIo {
    pub fn new(pci_root: PciRoot) -> Self {
        PciConfigIo {
            pci_root,
            config_address: 0,
        }
    }

    fn config_space_read(&mut self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (bus, device, function, register) =
            parse_config_address(self.config_address & !0x8000_0000);
        self.pci_root
            .config_space_read(bus, device, function, register)
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return;
        }

        let (bus, device, function, register) =
            parse_config_address(self.config_address & !0x8000_0000);
        self.pci_root
            .config_space_write(bus, device, function, register, offset, data)
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                (data[0] as u32) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 16),
                ((data[1] as u32) << 8 | data[0] as u32) << (offset * 16),
            ),
            4 => (0xffff_ffff, LittleEndian::read_u32(data)),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciConfigIo {
    fn debug_label(&self) -> String {
        format!("pci config io-port 0x{:03x}", self.config_address)
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // `offset` is relative to 0xcf8
        let value = match offset {
            0...3 => self.config_address,
            4...7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data {
                *d = 0xff;
            }
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        // `offset` is relative to 0xcf8
        match offset {
            o @ 0...3 => self.set_config_address(o, data),
            o @ 4...7 => self.config_space_write(o - 4, data),
            _ => (),
        };
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    /// PCI root bridge.
    pci_root: PciRoot,
}

impl PciConfigMmio {
    pub fn new(pci_root: PciRoot) -> Self {
        PciConfigMmio { pci_root }
    }

    fn config_space_read(&mut self, config_address: u32) -> u32 {
        let (bus, device, function, register) = parse_config_address(config_address);
        self.pci_root
            .config_space_read(bus, device, function, register)
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        let (bus, device, function, register) = parse_config_address(config_address);
        self.pci_root
            .config_space_write(bus, device, function, register, offset, data)
    }
}

impl BusDevice for PciConfigMmio {
    fn debug_label(&self) -> String {
        "pci config mmio".to_owned()
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end > 4 || offset > u32::max_value() as u64 {
            for d in data {
                *d = 0xff;
            }
            return;
        }

        let value = self.config_space_read(offset as u32);
        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if offset > u32::max_value() as u64 {
            return;
        }
        self.config_space_write(offset as u32, offset % 4, data)
    }
}

// Parse the CONFIG_ADDRESS register to a (bus, device, function, register) tuple.
fn parse_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 16;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 11;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 8;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3f;

    let bus_number = ((config_address >> BUS_NUMBER_OFFSET) & BUS_NUMBER_MASK) as usize;
    let device_number = ((config_address >> DEVICE_NUMBER_OFFSET) & DEVICE_NUMBER_MASK) as usize;
    let function_number =
        ((config_address >> FUNCTION_NUMBER_OFFSET) & FUNCTION_NUMBER_MASK) as usize;
    let register_number =
        ((config_address >> REGISTER_NUMBER_OFFSET) & REGISTER_NUMBER_MASK) as usize;

    (bus_number, device_number, function_number, register_number)
}
