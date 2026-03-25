///  IMPORTS 

use clap::Parser;
use pcap::{Capture, Device};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use std::net::Ipv6Addr;
use anyhow::{Context, Result};
use colored::*;
use chrono::Local;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, Duration};

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

    /// Save capture to a .pcap file e.g --pcap-out capture.pcap
    #[arg(long)]
    pcap_out: Option<String>,

    /// Save capture to a JSON file e.g --json-out capture.json
    #[arg(long)]
    json_out: Option<String>,

    /// Print each packet as JSON to stdout
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Show traffic statistics summary at end of session
    #[arg(long, default_value_t = false)]
    stats: bool,

     /// Stop capture after N seconds e.g --timeout 30
    #[arg(long)]
    timeout: Option<u64>,

    /// Filter by protocol: tcp, udp, icmp, dns, http
    #[arg(long)]
    protocol: Option<String>,

    /// Enable promiscuous mode (capture all packets on the network)
    #[arg(long, default_value_t = true)]
    promisc: bool,
}

/// Data Structures

#[derive(Serialize, Deserialize, Debug)]
struct PacketRecord {
    number: usize,
    timestamp: String,
    bytes: u32,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    protocol: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    transport: Option<String>,
    payload_bytes: usize,
    payload_preview: String,
}

#[derive(Debug, Default)]
struct Stats {
    total_packets: usize,
    total_bytes: u64,
    tcp_count: usize,
    udp_count: usize,
    icmp_count: usize,
    dns_count: usize,
    http_count: usize,
    src_ips: HashMap<String, usize>,
    dst_ips: HashMap<String, usize>,
    src_ports: HashMap<u16, usize>,
    dst_ports: HashMap<u16, usize>,
}

impl Stats {
    fn new() -> Self {
        Self::default()
    }
    fn update(&mut self, record: &PacketRecord, src_port: u16, dst_port: u16) {
        self.total_packets += 1;
        self.total_bytes += record.bytes as u64;

        if let Some(ref t) = record.transport {
            match t.as_str() {
                "TCP"   => self.tcp_count += 1,
                "UDP"   => self.udp_count += 1,
                "ICMPv4" | "ICMPv6" => self.icmp_count += 1,
                _ => {}
            }
        }

        // Count DNS and HTTP by port
        if src_port == 53 || dst_port == 53 {
            self.dns_count += 1;
        }
        if src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080 {
            self.http_count += 1;
        }

        if let Some(ref ip) = record.src_ip {
            *self.src_ips.entry(ip.clone()).or_insert(0) += 1;
        }
        if let Some(ref ip) = record.dst_ip {
            *self.dst_ips.entry(ip.clone()).or_insert(0) += 1;
        }

        if src_port > 0 {
            *self.src_ports.entry(src_port).or_insert(0) += 1;
        }
        if dst_port > 0 {
            *self.dst_ports.entry(dst_port).or_insert(0) += 1;
        }
    }

    fn print_summary(&self) {
        println!("\n{}", "═".repeat(60).cyan());
        println!("{}", "  CAPTURE SUMMARY".bold().cyan());
        println!("{}", "═".repeat(60).cyan());

        println!(
            "  {}  {}    {}  {}",
            "Total Packets:".bold(), self.total_packets,
            "Total Bytes:".bold(), self.total_bytes
        );

        println!("\n  {}", "Protocol Breakdown:".bold());
        println!("  TCP:    {}", self.tcp_count.to_string().cyan());
        println!("  UDP:    {}", self.udp_count.to_string().yellow());
        println!("  ICMP:   {}", self.icmp_count.to_string().red());
        println!("  DNS:    {}", self.dns_count.to_string().magenta());
        println!("  HTTP:   {}", self.http_count.to_string().green());

        // Top 5 source IPs
        println!("\n  {}", "Top Source IPs:".bold());
        let mut src_ips: Vec<_> = self.src_ips.iter().collect();
        src_ips.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in src_ips.iter().take(5) {
            println!("  {:>5}  {}", count.to_string().white(), ip.cyan());
        }

        // Top 5 destination IPs
        println!("\n  {}", "Top Destination IPs:".bold());
        let mut dst_ips: Vec<_> = self.dst_ips.iter().collect();
        dst_ips.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in dst_ips.iter().take(5) {
            println!("  {:>5}  {}", count.to_string().white(), ip.cyan());
        }

        //Top source ports
        println!("\n  {}", "Top Source Ports:".bold());
        let mut src_ports: Vec<_> = self.src_ports.iter().collect();
        src_ports.sort_by(|a, b| b.1.cmp(a.1));
        for (port, count) in src_ports.iter().take(5) {
            println!("  {:>5}  port {}", count.to_string().white(), port.to_string().yellow());
        }

        // Top 5 destination ports
        println!("\n  {}", "Top Destination Ports:".bold());
        let mut dst_ports: Vec<_> = self.dst_ports.iter().collect();
        dst_ports.sort_by(|a, b| b.1.cmp(a.1));
        for (port, count) in dst_ports.iter().take(5) {
            println!("  {:>5}  port {}", count.to_string().white(), port.to_string().yellow());
        }

        println!("{}", "═".repeat(60).cyan());
    }
}

///  MAIN 

fn main() -> Result<()> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    // Ctrl+c handler
     let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");


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
                println!("  {} {}", "→".cyan(), dev.name.green());
            }
            return Ok(());
        }
    };

    println!("{} {}", "Capturing on:".bold(), device.name.cyan().bold());

    if args.promisc {
        println!("{}", "Promiscuous mode: ON".dimmed());
    }

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(5000)
        .timeout(100)
        .open()?;

    if let Some(filter_expr) = &args.filter {
        cap.filter(filter_expr, true)
            .with_context(|| format!("Invalid BPF filter: '{}'", filter_expr))?;
        println!("{} {}", "Filter:".bold(), filter_expr.yellow());
    }

     if let Some(proto) = &args.protocol {
        println!("{} {}", "Protocol filter:".bold(), proto.yellow());
    }

    if let Some(secs) = args.timeout {
        println!("{} {}s", "Timeout:".bold(), secs.to_string().yellow());
    }

    // ── Open .pcap save file if requested ─────────────────────────────────────
    let mut savefile = match &args.pcap_out {
        Some(path) => {
            let sf = cap.savefile(path.as_str())
                .with_context(|| format!("Could not create pcap file: '{}'", path))?;
            println!("{} {}", "Saving .pcap to:".bold(), path.green());
            Some(sf)
        }
        None => None,
    };

    // ── Open JSON output file if requested ────────────────────────────────────
    let mut json_file: Option<File> = match &args.json_out {
        Some(path) => {
            let f = File::create(path)
                .with_context(|| format!("Could not create JSON file: '{}'", path))?;
            println!("{} {}", "Saving JSON to:".bold(), path.green());
            Some(f)
        }
        None => None,
    };

    // Write JSON array opening bracket
    if let Some(ref mut f) = json_file {
        writeln!(f, "[")?;
    }

    println!("{}", "─".repeat(60).dimmed());

    // ── Capture loop ──────────────────────────────────────────────────────────
    let mut packet_count = 0;
    let mut json_records: Vec<PacketRecord> = Vec::new();
    let mut stats = Stats::new();
    let show_stats = args.stats || args.count == 0;
    let start_time = Instant::now();
    let timeout_duration = args.timeout.map(Duration::from_secs);

    while running.load(Ordering::SeqCst) && (args.count == 0 || packet_count < args.count) {

        // Timeout check
        if let Some(duration) = timeout_duration {
            if start_time.elapsed() >= duration {
                println!("{}", "Timeout reached.".yellow().bold());
                break;
            }
        }

        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();

                if let Some(ref mut sf) = savefile {
                    sf.write(&packet);
                }

                match SlicedPacket::from_ethernet(packet.data) {
                    Ok(sliced) => {
                        let record = build_record(
                            packet_count,
                            &timestamp,
                            packet.header.len,
                            &sliced,
                        );

                        let src_port = record.src_port.unwrap_or(0);
                        let dst_port = record.dst_port.unwrap_or(0);

                        // ── Protocol filter ───────────────────────────────────
                        if let Some(ref proto) = args.protocol {
                            let matched = match proto.to_lowercase().as_str() {
                                "tcp"  => record.transport.as_deref() == Some("TCP"),
                                "udp"  => record.transport.as_deref() == Some("UDP"),
                                "icmp" => matches!(
                                    record.transport.as_deref(),
                                    Some("ICMPv4") | Some("ICMPv6")
                                ),
                                "dns"  => src_port == 53 || dst_port == 53,
                                "http" => src_port == 80 || dst_port == 80
                                       || src_port == 8080 || dst_port == 8080,
                                _ => true,
                            };

                            if !matched {
                                // decrement count so skipped packets don't count
                                packet_count -= 1;
                                continue;
                            }
                        }

                        println!(
                            "\n{} {} {} {}",
                            format!("[#{}]", packet_count).bold().white(),
                            timestamp.dimmed(),
                            "│".dimmed(),
                            format!("{} bytes", packet.header.len).dimmed()
                        );

                        analyze_packet(sliced);

                        if args.json {
                            println!("{}", serde_json::to_string_pretty(&record)?);
                        }

                        if show_stats {
                            stats.update(&record, src_port, dst_port);
                        }

                        json_records.push(record);
                    }
                    Err(err) => println!("{} {:?}", "Parse error:".red().bold(), err),
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => {
                println!("{} {:?}", "Capture error:".red().bold(), err);
                break;
            }
        }
    }

    // ── Write JSON file ───────────────────────────────────────────────────────
    if let Some(ref mut f) = json_file {
        for (i, record) in json_records.iter().enumerate() {
            let comma = if i < json_records.len() - 1 { "," } else { "" };
            writeln!(f, "  {}{}", serde_json::to_string_pretty(record)?, comma)?;
        }
        writeln!(f, "]")?;
        println!("{}", "JSON file written successfully.".green().bold());
    }

    //Print stats summary
    if show_stats {
        stats.print_summary();
    }

    Ok(())
}

/// build packet record

fn build_record(
    number: usize,
    timestamp: &str,
    bytes: u32,
    packet: &SlicedPacket,
) -> PacketRecord {
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut protocol = None;

    match &packet.ip {
        Some(InternetSlice::Ipv4(ipv4, _)) => {
            src_ip = Some(ipv4.source_addr().to_string());
            dst_ip = Some(ipv4.destination_addr().to_string());
            protocol = Some(format!("{}", ipv4.protocol()));
        }
        Some(InternetSlice::Ipv6(ipv6, _)) => {
            src_ip = Some(Ipv6Addr::from(ipv6.source_addr()).to_string());
            dst_ip = Some(Ipv6Addr::from(ipv6.destination_addr()).to_string());
            protocol = Some(format!("{}", ipv6.next_header()));
        }
        None => {}
    }

    let mut src_port = None;
    let mut dst_port = None;
    let mut transport = None;

    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            src_port = Some(tcp.source_port());
            dst_port = Some(tcp.destination_port());
            transport = Some("TCP".to_string());
        }
        Some(TransportSlice::Udp(udp)) => {
            src_port = Some(udp.source_port());
            dst_port = Some(udp.destination_port());
            transport = Some("UDP".to_string());
        }
        Some(TransportSlice::Icmpv4(_)) => transport = Some("ICMPv4".to_string()),
        Some(TransportSlice::Icmpv6(_)) => transport = Some("ICMPv6".to_string()),
        _ => {}
    }

    let payload = &packet.payload;
    let preview_len = std::cmp::min(16, payload.len());
    let payload_preview = payload[0..preview_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");

    PacketRecord {
        number,
        timestamp: timestamp.to_string(),
        bytes,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        transport,
        payload_bytes: payload.len(),
        payload_preview,
    }
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