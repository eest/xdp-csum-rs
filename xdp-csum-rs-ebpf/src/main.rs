#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, helpers::r#gen::bpf_csum_diff, macros::xdp, programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
};

// FIXME: Not sure how to make eBPF verifier happy with variable icmp len
// FIXME: It seems going over an EXPECTED_ICMP_LEN of 515 bytes will make bpf_csum_diff
// return -22 (-EINVAL), we probably need to further chunk up the calls in this
// case, maybe around 512 bytes or something.
const EXPECTED_ICMP_LEN: usize = 64;

// bpf_csum_diff expects length to be a multiple of 4
const REMAINDER_BUF_SIZE: usize = 4;
const IPV4_MAXLEN: usize = 60;

#[xdp]
pub fn xdp_csum_rs(ctx: XdpContext) -> u32 {
    match try_xdp_csum_rs(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// https://aya-rs.dev/book/start/parsing-packets/#__codelineno-1-42
fn try_xdp_csum_rs(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            // mut needed so we can set the exisitng checksum to 0 prior to running bpf_csum_diff
            let ipv4hdr_mut: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;

            match unsafe { (*ipv4hdr_mut).proto } {
                IpProto::Icmp => {
                    let ip_hdr_len = (unsafe { (*ipv4hdr_mut).ihl() } as usize) * 4;
                    info!(&ctx, "ip_hdr_len: {}", ip_hdr_len);

                    let icmp_offset = EthHdr::LEN + ip_hdr_len;
                    info!(&ctx, "icmp_offset: {}", icmp_offset);

                    // Calculate ICMP payload length
                    let ip_total_len =
                        unsafe { u16::from_be_bytes((*ipv4hdr_mut).tot_len) } as usize;

                    info!(&ctx, "ip_total_len: {}", ip_total_len);

                    // https://github.com/torvalds/linux/blob/155a3c003e555a7300d156a5252c004c392ec6b0/tools/testing/selftests/bpf/progs/xdp_synproxy_kern.c#L793-L797
                    if ipv4hdr_mut as usize + IPV4_MAXLEN > ctx.data_end() {
                        return Err(());
                    }

                    let orig_ipv4_csum = unsafe { (*ipv4hdr_mut).check };
                    info!(
                        &ctx,
                        "original IPv4 checksum: 0x{:x}{:x}", orig_ipv4_csum[0], orig_ipv4_csum[1]
                    );

                    // Clear checksum field before calculating new checksum
                    unsafe { (*ipv4hdr_mut).check = [0, 0] };

                    let recalc_ipv4_csum = unsafe {
                        bpf_csum_diff(
                            core::ptr::null_mut(),
                            0,
                            ipv4hdr_mut as *mut u32,
                            ((*ipv4hdr_mut).ihl() * 4) as u32,
                            0,
                        )
                    };

                    // Reset the original check field so the packet is valid again
                    unsafe { (*ipv4hdr_mut).check = orig_ipv4_csum };

                    if recalc_ipv4_csum < 0 {
                        info!(&ctx, "invalid recalc_ipv4_csum {}", recalc_ipv4_csum);
                        return Ok(xdp_action::XDP_PASS);
                    }

                    let folded_ipv4_csum = csum_fold_helper(recalc_ipv4_csum as u64);

                    info!(
                        &ctx,
                        "recalculated IPv4 checkum: 0x{:x}",
                        u16::to_be(folded_ipv4_csum)
                    );

                    if u16::to_be(folded_ipv4_csum)
                        != unsafe { u16::from_be_bytes((*ipv4hdr_mut).check) }
                    {
                        info!(&ctx, "IP checksum is invalid");
                    } else {
                        info!(&ctx, "IP checksum is valid");
                    }

                    let icmphdr_mut: *mut IcmpHdr = ptr_at_mut(&ctx, EthHdr::LEN + ip_hdr_len)?;

                    let icmp_len = ctx.data_end() - icmphdr_mut as usize;
                    info!(&ctx, "icmp_len: {}", icmp_len);

                    if icmp_len > EXPECTED_ICMP_LEN {
                        info!(
                            &ctx,
                            "icmp_len ({}) is larger than expected ICMP len ({})",
                            icmp_len,
                            EXPECTED_ICMP_LEN
                        );
                        return Ok(xdp_action::XDP_PASS);
                    }

                    if icmphdr_mut as usize + EXPECTED_ICMP_LEN > ctx.data_end() {
                        info!(&ctx, "expected ICMP len is larger than size of packet data");
                        return Ok(xdp_action::XDP_PASS);
                    }

                    info!(&ctx, "original ICMP checksum: 0x{:x}", unsafe {
                        u16::from_be((*icmphdr_mut).checksum)
                    });

                    // Handle uneven data lengths since bpf_csum_diff() expects the length to
                    // be a multiple of 4
                    let icmp_len_remainder = icmp_len % REMAINDER_BUF_SIZE;
                    if icmp_len_remainder != 0 {
                        info!(
                            &ctx,
                            "icmp_len is not a multiple of 4, remainder {}", icmp_len_remainder
                        );
                    }

                    let icmp_remainder_offset = icmp_len - icmp_len_remainder;

                    let orig_icmp_checksum = unsafe { (*icmphdr_mut).checksum };

                    // As for IPv4 checksum also reset it for ICMP prior to recalculating it
                    unsafe { (*icmphdr_mut).checksum = 0 };

                    let mut icmp_csum = unsafe {
                        bpf_csum_diff(
                            core::ptr::null_mut(),
                            0,
                            icmphdr_mut as *mut u32,
                            icmp_remainder_offset as u32,
                            0,
                        )
                    };

                    // If there was a remainder we need to add on the final 1-3 bytes padded with
                    // zeroes using the first call as the seed.
                    if icmp_len_remainder != 0 {
                        let mut remainder_buf: [u8; REMAINDER_BUF_SIZE] = [0; REMAINDER_BUF_SIZE];
                        info!(
                            &ctx,
                            "initial remainder buf: [{},{},{},{}]",
                            remainder_buf[0],
                            remainder_buf[1],
                            remainder_buf[2],
                            remainder_buf[3]
                        );
                        for i in 0..icmp_len_remainder {
                            let offset = icmp_remainder_offset + i;
                            info!(
                                &ctx,
                                "iterating over remainder at {}, offset: {}", i, offset
                            );
                            let icmphdr_remainder_byte: *const u8 =
                                ptr_at(&ctx, EthHdr::LEN + ip_hdr_len + offset)?;
                            info!(&ctx, "icmphdr_remainder_byte: {:x}", unsafe {
                                *icmphdr_remainder_byte
                            });
                            remainder_buf[i] = unsafe { *icmphdr_remainder_byte };
                        }
                        info!(
                            &ctx,
                            "filled in remainder buf: [{},{},{},{}]",
                            remainder_buf[0],
                            remainder_buf[1],
                            remainder_buf[2],
                            remainder_buf[3]
                        );
                        icmp_csum = unsafe {
                            bpf_csum_diff(
                                core::ptr::null_mut(),
                                0,
                                remainder_buf.as_ptr() as *mut u32,
                                REMAINDER_BUF_SIZE as u32,
                                icmp_csum as u32,
                            )
                        };
                    }

                    // Add back the checksum now that we are done with verifications.
                    unsafe { (*icmphdr_mut).checksum = orig_icmp_checksum };

                    if icmp_csum < 0 {
                        info!(&ctx, "invalid call to bpf_csum_diff for ICMP packet: {}", icmp_csum);
                        return Ok(xdp_action::XDP_PASS);
                    }

                    let folded_icmp_csum = csum_fold_helper(icmp_csum as u64);

                    info!(
                        &ctx,
                        "ICMP recalculated checksum: 0x{:x}",
                        u16::to_be(folded_icmp_csum)
                    );

                    if u16::to_be(folded_icmp_csum)
                        != unsafe { u16::from_be((*icmphdr_mut).checksum) }
                    {
                        info!(&ctx, "ICMP checksum is invalid");
                    } else {
                        info!(&ctx, "ICMP checksum is valid");
                    }
                }
                _ => return Ok(xdp_action::XDP_PASS),
            }
        }
        _ => {}
    }
    Ok(xdp_action::XDP_PASS)
}

// https://aya-rs.dev/book/start/parsing-packets/#__codelineno-1-29
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// mut needed for modifiying packet (e.g. resetting checksum field prior to running bpf_csum_diff)
#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

// https://github.com/riyaolin/aya-ebpf-lb-rs/blob/55bc95f25fc2dc2680cf8add874ad32dcdd3bedd/lb/lb-ebpf/src/main.rs#L60
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return !(csum as u16);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
