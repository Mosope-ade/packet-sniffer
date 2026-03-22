///  IMPORTS 

use clap::Parser;
use pcap::{Capture, Device};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use std::net::Ipv6Addr;
use anyhow::{Context, Result};
use colored::*;
use chrono::Local;

/// CLI ARGUMENTS 

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

///  MAIN 

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

    //  Apply BPF filter if provided 
    if let Some(filter_expr) = &args.filter {
        cap.filter(filter_expr, true)
            .with_context(|| format!("Invalid BPF filter expression: '{}'", filter_expr))?;
        println!("{} {}", "Filter:".bold(), filter_expr.yellow());
    }

    println!("{}", "_".repeat(60).dimmed());

    //  Capture loop 
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

///  PACKET ANALYSIS 


fn analyze_packet(packet: SlicedPacket) {
    let mut src_port = 0u16;
    let mut dest_port = 0u16;
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
            src_port = tcp.source_port();
            dest_port = tcp.destination_port();
             println!(
                "  {} port {} {} {}",
                "TCP".cyan().bold(),
                src_port.to_string().white(),
                "→".dimmed(),
                dest_port.to_string().white()
            );
            println!(
                "  {} SYN={} ACK={} FIN={} RST={}",
                "Flags:".dimmed(),
                tcp.syn().to_string().yellow(),
                tcp.ack().to_string().yellow(),
                tcp.fin().to_string().yellow(),
                tcp.rst().to_string().yellow()
            );
            println!(
                 "  {} {}  {} {}",
                "Seq:".dimmed(), tcp.sequence_number(),
                "Win:".dimmed(), tcp.window_size()
            );
        }
        Some(TransportSlice::Udp(udp)) => {
            src_port = udp.source_port();
            dest_port = udp.destination_port();
            println!(
                "  {} port {} {} {}  len={}",
                "UDP".yellow().bold(),
                src_port.to_string().white(),
                "→".dimmed(),
                dest_port.to_string().white(),
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

    // Payload decoders
    let payload = &packet.payload;
    
    if !payload.is_empty() {
        // http decoder
        if src_port == 80 || dest_port == 80 || src_port == 8080 || dest_port == 8080 {
            decode_http(payload);
        }

        // dns decoder
        if src_port == 53 || dest_port == 53 {
            decode_dns(payload);
        }
    }    

    // Payload preview
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

/// ─── PROTOCOL DECODERS ────────────────────────────────────────────────────────

fn decode_http(payload: &[u8]) {
    // HTTP is text-based — try to parse payload as UTF-8
    if let Ok(text) = std::str::from_utf8(payload) {
        let first_line = text.lines().next().unwrap_or("");

        // Detect HTTP request methods
        let is_request = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                          "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "]
            .iter()
            .any(|m| first_line.starts_with(m));

        // Detect HTTP response
        let is_response = first_line.starts_with("HTTP/");

        if is_request {
            println!("  {} {}", "HTTP Request:".green().bold(), first_line.green());

            // Print useful headers
            for line in text.lines().skip(1) {
                if line.is_empty() { break; } // end of headers
                if line.starts_with("Host:")
                    || line.starts_with("User-Agent:")
                    || line.starts_with("Content-Type:")
                    || line.starts_with("Content-Length:")
                    || line.starts_with("Authorization:")
                {
                    println!("    {} {}", "↳".dimmed(), line.dimmed());
                }
            }
        } else if is_response {
            println!("  {} {}", "HTTP Response:".green().bold(), first_line.green());

            // Print useful response headers
            for line in text.lines().skip(1) {
                if line.is_empty() { break; }
                if line.starts_with("Content-Type:")
                    || line.starts_with("Content-Length:")
                    || line.starts_with("Server:")
                    || line.starts_with("Location:")
                {
                    println!("    {} {}", "↳".dimmed(), line.dimmed());
                }
            }
        }
    }
}

fn decode_dns(payload: &[u8]) {
    // DNS packet structure (manual decode — no external crate needed)
    // Header is 12 bytes minimum
    if payload.len() < 12 {
        return;
    }

    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]); // question count
    let ancount = u16::from_be_bytes([payload[6], payload[7]]); // answer count

    let is_response = (flags & 0x8000) != 0;
    let rcode = flags & 0x000F; // response code

    if is_response {
        println!(
            "  {} id={} questions={} answers={} {}",
            "DNS Response:".magenta().bold(),
            id,
            qdcount,
            ancount,
            if rcode == 0 { "OK".green() } else { format!("RCODE={}", rcode).red() }
        );
    } else {
        println!(
            "  {} id={} questions={}",
            "DNS Query:".magenta().bold(),
            id,
            qdcount
        );
    }

    // Parse the question section to extract the queried domain name
    if qdcount > 0 {
        if let Some(domain) = parse_dns_name(payload, 12) {
            println!("    {} {}", "↳ Domain:".dimmed(), domain.magenta());
        }
    }
}

fn parse_dns_name(payload: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();

    loop {
        if offset >= payload.len() {
            return None;
        }

        let len = payload[offset] as usize;

        // 0 length = end of name
        if len == 0 {
            break;
        }

        // Pointer (compression) — top two bits are 11
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= payload.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | payload[offset + 1] as usize;
            return parse_dns_name(payload, ptr);
        }

        offset += 1;

        if offset + len > payload.len() {
            return None;
        }

        let label = std::str::from_utf8(&payload[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    Some(labels.join("."))
}