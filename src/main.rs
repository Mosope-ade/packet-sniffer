/// ─── IMPORTS ──────────────────────────────────────────────────────────────────

use clap::Parser;
use pcap::{Capture, Device};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use std::net::Ipv6Addr;
use anyhow::{Context, Result};
use colored::*;
use chrono::Local;

/// ─── CLI ARGUMENTS ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]

struct Args {
    /// Network interface to capture on
    #[arg(short, long)]
    interface: Option<String>,

    /// Number of packets to capture (0 for unlimited)
    #[arg(short, long, default_value_t = 10)]
    count: usize,

    /// BPF filter expression e.g. "tcp port 80" or "host 192.168.1.1"
    #[arg(short, long)]
    filter: Option<String>,

     /// Disable colored output (useful when piping to a file)
    #[arg(long, default_value_t = false)]
    no_color: bool,
}

/// ─── MAIN ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    let device = match &args.interface {
        Some(interface_name) => {
            Device::list()?
                .into_iter()
                .find(|d| d.name == *interface_name)
                .with_context(|| format!("Interface '{}' not found", interface_name))?
        }
        None => {
            println!("Available network interfaces:");
            for dev in Device::list()? {
                println!("- {}: {}", "→".cyan(), dev.name.green());
            }
            return Ok(());
        }
    };

    println!("{} {}", "Capturing on:".bold(), device.name.cyan().bold());

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(5000)
        .timeout(100)
        .open()?;

    // ── Apply BPF filter if provided ──────────────────────────────────────────
    if let Some(filter_expr) = &args.filter {
        cap.filter(filter_expr, true)
            .with_context(|| format!("Invalid BPF filter expression: '{}'", filter_expr))?;
        println!("{} {}", "Filter:".bold(), filter_expr.yellow());
    }

    println!("{}", "_".repeat(60).dimmed());

    // ── Capture loop ──────────────────────────────────────────────────────────
    let mut packet_count = 0;
    while args.count == 0 || packet_count < args.count {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                println!(
                    "\n{} {} {} {}",
                    format!("[#{}]", packet_count).bold().white(),
                    timestamp.dimmed(),
                    "│".dimmed(),
                    format!("{} bytes", packet.header.len).dimmed()
                );

                match SlicedPacket::from_ethernet(packet.data) {
                    Ok(value) => analyze_packet(value),
                    Err(err) => println!("{} {:?}", "Error parsing packet:".red().bold(), err),
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => {
                println!("{} {:?}", "Error receiving packet:".red().bold(), err);
                break;
            }
        }
    }

    Ok(())
}

/// ─── PACKET ANALYSIS ──────────────────────────────────────────────────────────

fn analyze_packet(packet: SlicedPacket) {
    if let Some(link) = &packet.link {
        println!("{} {:?}", "Link layer:".dimmed(), link);
    }


    //network layer
    match &packet.ip {
        Some(InternetSlice::Ipv4(ipv4, _)) => {
            let source = ipv4.source_addr();
            let dest = ipv4.destination_addr();
             println!(
                "  {} {} {} {}",
                "IPv4:".blue().bold(),
                source.to_string().white(),
                "→".dimmed(),
                dest.to_string().white()
            );
            println!("  {} {}", "Protocol:".dimmed(), ipv4.protocol().to_string().blue());
        }
        Some(InternetSlice::Ipv6(ipv6, _)) => {
            let source = Ipv6Addr::from(ipv6.source_addr());
            let dest = Ipv6Addr::from(ipv6.destination_addr());
            println!(
                "  {} {} {} {}",
                "IPv6:".blue().bold(),
                source.to_string().white(),
                "→".dimmed(),
                dest.to_string().white()
            );
            println!("  {} {}", "Next Header:".dimmed(), ipv6.next_header().to_string().blue());
        }
        None => println!("  {}", "No IP layer".dimmed()),
    }

    //transport layer
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
             println!(
                "  {} port {} {} {}",
                "TCP".cyan().bold(),
                tcp.source_port().to_string().white(),
                "→".dimmed(),
                tcp.destination_port().to_string().white()
            );
        }
        Some(TransportSlice::Udp(udp)) => {
            println!(
                "  {} port {} {} {}  len={}",
                "UDP".yellow().bold(),
                udp.source_port().to_string().white(),
                "→".dimmed(),
                udp.destination_port().to_string().white(),
                udp.length()
            );
        }
        Some(TransportSlice::Icmpv4(_)) => println!("{}", "ICMPv4 packet".red().bold()),
        Some(TransportSlice::Icmpv6(_)) => println!("{}", "ICMPv6 packet".red().bold()),
        Some(TransportSlice::Unknown(u)) => {
            println!("  {} {}", "Unknown protocol:".dimmed(), u)
        }
        None => println!("{}", "No transport layer".dimmed()),
    }

    let payload = &packet.payload;
    if !payload.is_empty() {
        let preview_len = std::cmp::min(16, payload.len());
        let hex: Vec<String> = payload[0..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!(
            "  {} {} bytes  {}",
            "Payload:".dimmed(),
            payload.len(),
            hex.join(" ").dimmed()
        );
    } else {
        println!("  {}", "Payload: empty".dimmed());
    }
}