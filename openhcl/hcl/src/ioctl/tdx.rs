// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backing for TDX partitions.

use super::hcl_tdcall;
use super::mshv_tdcall;
use super::HclVp;
use super::MshvVtl;
use super::NoRunner;
use super::ProcessorRunner;
use crate::protocol::tdx_tdg_vp_enter_exit_info;
use crate::protocol::tdx_vp_context;
use crate::protocol::tdx_vp_state;
use crate::GuestVtl;
use hvdef::HvRegisterName;
use hvdef::HvRegisterValue;
use memory_range::MemoryRange;
use sidecar_client::SidecarVp;
use std::os::fd::AsRawFd;
use std::ptr::addr_of;
use std::ptr::addr_of_mut;
use std::ptr::NonNull;
use tdcall::tdcall_vp_invgla;
use tdcall::tdcall_vp_rd;
use tdcall::tdcall_vp_wr;
use tdcall::Tdcall;
use x86defs::tdx::TdCallResult;
use x86defs::tdx::TdCallResultCode;
use x86defs::tdx::TdGlaVmAndFlags;
use x86defs::tdx::TdVpsClassCode;
use x86defs::tdx::TdgMemPageAttrWriteR8;
use x86defs::tdx::TdgMemPageGpaAttr;
use x86defs::tdx::TdxContextCode;
use x86defs::tdx::TdxExtendedFieldCode;
use x86defs::tdx::TdxGlaListInfo;
use x86defs::tdx::TdxL2Ctls;
use x86defs::tdx::TdxL2EnterGuestState;
use x86defs::tdx::TdxVmFlags;
use x86defs::vmx::VmcsField;

/// Runner backing for TDX partitions.
pub struct Tdx {
    apic: NonNull<[u32; 1024]>,
}

impl MshvVtl {
    /// Issues a tdcall to set page attributes.
    pub fn tdx_set_page_attributes(
        &self,
        range: MemoryRange,
        attributes: TdgMemPageGpaAttr,
        mask: TdgMemPageAttrWriteR8,
    ) -> Result<(), TdCallResultCode> {
        tdcall::set_page_attributes(&mut MshvVtlTdcall(self), range, attributes, mask)
    }

    /// Issues a tdcall to accept pages, optionally also setting attributes.
    ///
    /// These operations are combined because this code tries accepting at 2MB
    /// granularity first and then falls back to 4KB. A separate call to
    /// [`Self::tdx_set_page_attributes`] has to re-derive the appropriate
    /// granularity.
    pub fn tdx_accept_pages(
        &self,
        range: MemoryRange,
        attributes: Option<(TdgMemPageGpaAttr, TdgMemPageAttrWriteR8)>,
    ) -> Result<(), tdcall::AcceptPagesError> {
        let attributes = attributes
            .map_or(tdcall::AcceptPagesAttributes::None, |(attributes, mask)| {
                tdcall::AcceptPagesAttributes::Set { attributes, mask }
            });

        tdcall::accept_pages(&mut MshvVtlTdcall(self), range, attributes)
    }
}

impl ProcessorRunner<'_, Tdx> {
    /// Gets a reference to the TDX VP context that is unioned inside the run
    /// page.
    fn tdx_vp_context(&self) -> &tdx_vp_context {
        // SAFETY: the VP context will not be concurrently accessed by the
        // processor while this VP is in VTL2. This is a TDX partition so the
        // context union should be interpreted as a `tdx_vp_context`.
        unsafe { &*addr_of!((*self.run.as_ptr()).context).cast() }
    }

    /// Gets a mutable reference to the TDX VP context that is unioned inside
    /// the run page.
    fn tdx_vp_context_mut(&mut self) -> &mut tdx_vp_context {
        // SAFETY: the VP context will not be concurrently accessed by the
        // processor while this VP is in VTL2. This is a TDX partition so the
        // context union should be interpreted as a `tdx_vp_context`.
        unsafe { &mut *addr_of_mut!((*self.run.as_ptr()).context).cast() }
    }

    /// Gets a reference to the TDX enter guest state.
    pub fn tdx_enter_guest_state(&self) -> &TdxL2EnterGuestState {
        &self.tdx_vp_context().gpr_list
    }

    /// Gets a mutable reference to the TDX enter guest state.
    pub fn tdx_enter_guest_state_mut(&mut self) -> &mut TdxL2EnterGuestState {
        &mut self.tdx_vp_context_mut().gpr_list
    }

    /// Gets a reference to the tdx exit info from a VP.ENTER call.
    pub fn tdx_vp_enter_exit_info(&self) -> &tdx_tdg_vp_enter_exit_info {
        &self.tdx_vp_context().exit_info
    }

    /// Gets a reference to the tdx APIC page.
    pub fn tdx_apic_page(&self) -> &[u32; 1024] {
        // SAFETY: the APIC page will not be concurrently accessed by the processor
        // while this VP is in VTL2.
        unsafe { &*self.state.apic.as_ptr() }
    }

    /// Gets a mutable reference to the tdx APIC page.
    pub fn tdx_apic_page_mut(&mut self) -> &mut [u32; 1024] {
        // SAFETY: the APIC page will not be concurrently accessed by the processor
        // while this VP is in VTL2.
        unsafe { &mut *self.state.apic.as_ptr() }
    }

    /// Gets a reference to TDX VP specific state.
    pub fn tdx_vp_state(&self) -> &tdx_vp_state {
        &self.tdx_vp_context().vp_state
    }

    /// Gets a mutable reference to TDX VP specific state
    pub fn tdx_vp_state_mut(&mut self) -> &mut tdx_vp_state {
        &mut self.tdx_vp_context_mut().vp_state
    }

    /// Gets a reference to the TDX VP entry flags.
    pub fn tdx_vp_entry_flags(&self) -> &TdxVmFlags {
        &self.tdx_vp_context().entry_rcx
    }

    /// Gets a mutable reference to the TDX VP entry flags.
    pub fn tdx_vp_entry_flags_mut(&mut self) -> &mut TdxVmFlags {
        &mut self.tdx_vp_context_mut().entry_rcx
    }

    fn vmcs_field_code(field: VmcsField, vtl: GuestVtl) -> TdxExtendedFieldCode {
        let class_code = match vtl {
            GuestVtl::Vtl0 => TdVpsClassCode::VMCS_1,
            GuestVtl::Vtl1 => TdVpsClassCode::VMCS_2,
        };
        let field_size = match field.field_width() {
            x86defs::vmx::FieldWidth::Width16 => x86defs::tdx::FieldSize::Size16Bit,
            x86defs::vmx::FieldWidth::Width32 => x86defs::tdx::FieldSize::Size32Bit,
            x86defs::vmx::FieldWidth::Width64 => x86defs::tdx::FieldSize::Size64Bit,
            x86defs::vmx::FieldWidth::WidthNatural => x86defs::tdx::FieldSize::Size64Bit,
        };
        TdxExtendedFieldCode::new()
            .with_context_code(TdxContextCode::TD_VCPU)
            .with_class_code(class_code.0)
            .with_field_code(field.into())
            .with_field_size(field_size)
    }

    fn write_vmcs(&mut self, vtl: GuestVtl, field: VmcsField, mask: u64, value: u64) -> u64 {
        tdcall_vp_wr(
            &mut MshvVtlTdcall(&self.hcl.mshv_vtl),
            Self::vmcs_field_code(field, vtl),
            value,
            mask,
        )
        .expect("fatal vmcs access failure")
    }

    fn read_vmcs(&self, vtl: GuestVtl, field: VmcsField) -> u64 {
        tdcall_vp_rd(
            &mut MshvVtlTdcall(&self.hcl.mshv_vtl),
            Self::vmcs_field_code(field, vtl),
        )
        .expect("fatal vmcs access failure")
    }

    /// Write a 64-bit VMCS field.
    ///
    /// Only updates the bits that are set in `mask`. Returns the old value of
    /// the field.
    ///
    /// Panics if the field is not a 64-bit field, or if there is an error in
    /// the TDX module when writing the field.
    pub fn write_vmcs64(&mut self, vtl: GuestVtl, field: VmcsField, mask: u64, value: u64) -> u64 {
        assert!(matches!(
            field.field_width(),
            x86defs::vmx::FieldWidth::WidthNatural | x86defs::vmx::FieldWidth::Width64
        ));
        self.write_vmcs(vtl, field, mask, value)
    }

    /// Reads a 64-bit VMCS field.
    ///
    /// Panics if the field is not a 64-bit field, or if there is an error in
    /// the TDX module when reading the field.
    pub fn read_vmcs64(&self, vtl: GuestVtl, field: VmcsField) -> u64 {
        assert!(matches!(
            field.field_width(),
            x86defs::vmx::FieldWidth::WidthNatural | x86defs::vmx::FieldWidth::Width64
        ));
        self.read_vmcs(vtl, field)
    }

    /// Write a 32-bit VMCS field.
    ///
    /// Only updates the bits that are set in `mask`. Returns the old value of
    /// the field.
    ///
    /// Panics if the field is not a 32-bit field, or if there is an error in
    /// the TDX module when writing the field.
    pub fn write_vmcs32(&mut self, vtl: GuestVtl, field: VmcsField, mask: u32, value: u32) -> u32 {
        assert_eq!(field.field_width(), x86defs::vmx::FieldWidth::Width32);
        self.write_vmcs(vtl, field, mask.into(), value.into()) as u32
    }

    /// Reads a 32-bit VMCS field.
    ///
    /// Panics if the field is not a 32-bit field, or if there is an error in
    /// the TDX module when reading the field.
    pub fn read_vmcs32(&self, vtl: GuestVtl, field: VmcsField) -> u32 {
        assert_eq!(field.field_width(), x86defs::vmx::FieldWidth::Width32);
        self.read_vmcs(vtl, field) as u32
    }

    /// Write a 16-bit VMCS field.
    ///
    /// Only updates the bits that are set in `mask`. Returns the old value of
    /// the field.
    ///
    /// Panics if the field is not a 16-bit field, or if there is an error in
    /// the TDX module when writing the field.
    pub fn write_vmcs16(&mut self, vtl: GuestVtl, field: VmcsField, mask: u16, value: u16) -> u16 {
        assert_eq!(field.field_width(), x86defs::vmx::FieldWidth::Width16);
        self.write_vmcs(vtl, field, mask.into(), value.into()) as u16
    }

    /// Reads a 16-bit VMCS field.
    ///
    /// Panics if the field is not a 16-bit field, or if there is an error in
    /// the TDX module when reading the field.
    pub fn read_vmcs16(&self, vtl: GuestVtl, field: VmcsField) -> u16 {
        assert_eq!(field.field_width(), x86defs::vmx::FieldWidth::Width16);
        self.read_vmcs(vtl, field) as u16
    }

    /// Writes 64-bit word with index `i` of the MSR bitmap.
    ///
    /// Only updates the bits that are set in `mask`. Returns the old value of
    /// the word.
    ///
    /// Panics if there is an error in the TDX module when writing the word.
    pub fn write_msr_bitmap(&self, vtl: GuestVtl, i: u32, mask: u64, word: u64) -> u64 {
        let class_code = match vtl {
            GuestVtl::Vtl0 => TdVpsClassCode::MSR_BITMAPS_1,
            GuestVtl::Vtl1 => TdVpsClassCode::MSR_BITMAPS_2,
        };
        let field_code = TdxExtendedFieldCode::new()
            .with_context_code(TdxContextCode::TD_VCPU)
            .with_field_size(x86defs::tdx::FieldSize::Size64Bit)
            .with_field_code(i)
            .with_class_code(class_code.0);

        tdcall_vp_wr(
            &mut MshvVtlTdcall(&self.hcl.mshv_vtl),
            field_code,
            word,
            mask,
        )
        .unwrap()
    }

    /// Sets the L2_CTLS field of the VP.
    ///
    /// Returns the old value of the field.
    pub fn set_l2_ctls(&self, vtl: GuestVtl, value: TdxL2Ctls) -> Result<TdxL2Ctls, TdCallResult> {
        let field_code = match vtl {
            GuestVtl::Vtl0 => x86defs::tdx::TDX_FIELD_CODE_L2_CTLS_VM1,
            GuestVtl::Vtl1 => x86defs::tdx::TDX_FIELD_CODE_L2_CTLS_VM2,
        };
        tdcall_vp_wr(
            &mut MshvVtlTdcall(&self.hcl.mshv_vtl),
            field_code,
            value.into(),
            !0,
        )
        .map(Into::into)
    }

    /// Issues an INVGLA instruction for the VP.
    pub fn invgla(
        &self,
        gla_flags: TdGlaVmAndFlags,
        gla_info: TdxGlaListInfo,
    ) -> Result<(), TdCallResult> {
        tdcall_vp_invgla(&mut MshvVtlTdcall(&self.hcl.mshv_vtl), gla_flags, gla_info)
            .map(Into::into)
    }

    /// Gets the FPU state for the VP.
    pub fn fx_state(&self) -> &x86defs::xsave::Fxsave {
        &self.tdx_vp_context().fx_state
    }

    /// Sets the FPU state for the VP.
    pub fn fx_state_mut(&mut self) -> &mut x86defs::xsave::Fxsave {
        &mut self.tdx_vp_context_mut().fx_state
    }
}

impl super::private::BackingPrivate for Tdx {
    fn new(vp: &HclVp, sidecar: Option<&SidecarVp<'_>>) -> Result<Self, NoRunner> {
        assert!(sidecar.is_none());
        let super::BackingState::Tdx { apic_page } = &vp.backing else {
            return Err(NoRunner::MismatchedIsolation);
        };
        Ok(Self { apic: apic_page.0 })
    }

    fn try_set_reg(
        _runner: &mut ProcessorRunner<'_, Self>,
        _vtl: GuestVtl,
        _name: HvRegisterName,
        _value: HvRegisterValue,
    ) -> Result<bool, super::Error> {
        Ok(false)
    }

    fn must_flush_regs_on(_runner: &ProcessorRunner<'_, Self>, _name: HvRegisterName) -> bool {
        false
    }

    fn try_get_reg(
        _runner: &ProcessorRunner<'_, Self>,
        _vtl: GuestVtl,
        _name: HvRegisterName,
    ) -> Result<Option<HvRegisterValue>, super::Error> {
        Ok(None)
    }
}

struct MshvVtlTdcall<'a>(&'a MshvVtl);

impl Tdcall for MshvVtlTdcall<'_> {
    fn tdcall(&mut self, input: tdcall::TdcallInput) -> tdcall::TdcallOutput {
        let mut mshv_tdcall_args = {
            let tdcall::TdcallInput {
                leaf,
                rcx,
                rdx,
                r8,
                r9,
                r10,
                r11,
                r12,
                r13,
                r14,
                r15,
            } = input;

            // NOTE: Only TD module calls are supported by the kernel, so assert
            // that here before dispatching. Additionally, the kernel only
            // supports a limited set of input registers.
            assert_ne!(leaf, x86defs::tdx::TdCallLeaf::VP_VMCALL);
            assert_eq!(r10, 0);
            assert_eq!(r11, 0);
            assert_eq!(r12, 0);
            assert_eq!(r13, 0);
            assert_eq!(r14, 0);
            assert_eq!(r15, 0);

            mshv_tdcall {
                rax: leaf.0,
                rcx,
                rdx,
                r8,
                r9,
                r10_out: 0,
                r11_out: 0,
            }
        };

        // SAFETY: Calling tdcall ioctl with the correct arguments.
        unsafe {
            // NOTE: This ioctl should never fail, as the tdcall itself failing
            // is returned as output in the structure given by the kernel.
            hcl_tdcall(self.0.file.as_raw_fd(), &mut mshv_tdcall_args)
                .expect("todo handle tdcall ioctl error");
        }

        tdcall::TdcallOutput {
            rax: TdCallResult::from(mshv_tdcall_args.rax),
            rcx: mshv_tdcall_args.rcx,
            rdx: mshv_tdcall_args.rdx,
            r8: mshv_tdcall_args.r8,
            r10: mshv_tdcall_args.r10_out,
            r11: mshv_tdcall_args.r11_out,
        }
    }
}
