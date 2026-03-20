///COMMAND LINE ARGUMENTS

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]

struct Args {
    //Network interface to capture on
    #[arg(short, long)]
    interface: Option<String>,

    //Number of packets to capture (0 for unlimited)
    #[arg(short, long, default_value_t = 10)]
    count: usize,
}


///SETTING UP PACKET CAPTURE

fn main() -> Result<()> {
    let args = Args::parse();

    //list available devices if no interface provided
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
                println!("- {}: {}", dev.name, dev.desc.unwrap_or_default());
            }
            return Ok(());
        }
    };
    println!("Capturing on device {}", device.name);

    //CAPTURE HANDLE WITH SOME CONFIGURATIONS
    let mut cap = Capture::from_device(device)?
    .promisc(true)  //capture all packets
    .snaplen(5000)  //capture up to 5000 bytes of each packet
    .timeout(100)   //timeout of 100ms
    .open()?;

    //THE CAPTURE LOOP

    let mut packet_count = 0;
    while args.count == 0 || packet_count < args.count {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;

                println!("\n[Packet #{}] {} bytes", packet_count, packet.header.len);

                match SlicedPacket::from_ethernet(packet.data) {
                    Ok(value) => analyze_packet(value),
                    Err(err) => println!("Error parsing packet: {:?}", err),
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                //just try again on timeout
                continue;
            }
            Err(err) => {
                println!("Error receiving packet: {:?}", err);
                break;
            }
        }
    }

    fn analyze_packet(packet: SlicedPacket) {
        //analyze link layer
        if let Some(link) = &packet.link {
            println!("Link layer: {:?}", link);
        }

        //analyze network layer
        match &packet.ip {
            Some(InternetSlice::Ipv4(ipv4, _)) => {

                let source = ipv4.source_addr();
                let dest = ipv4.destination_addr();

                println!("IPv4: {} -> {}", source, dest);
                println!("Protocol: {}", ipv4.protocol());
            }
            Some(InternetSlice::Ipv6(ipv6, _)) => {
                let source = Ipv6Addr::from(ipv6.source_addr());
                let dest = Ipv6Addr::from(ipv6.destination_addr());

                println!("IPv6: {} -> {}", source, dest);
                println!("Next Header: {}", ipv6.next_header());
            }
            None => println!("No IP layer found"),
        }
    }

    //analyze transport layer
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            println!("TCP: Port {} -> {}", tcp.source_port(), tcp.destination_port());
            println!("Flags: SYN={} ACK={} FIN={} RST={}",
                tcp.syn(), tcp.ack(), tcp.fin(), tcp.rst());
            println!("Sequence: {}, Window: {}", tcp.sequence_number(), tcp.window_size());
        }

        Some(TransportSlice::Udp(udp)) => {
            println!("UDP: Port {} -> {}", udp.source_port(), udp.destination_port());
            println!("Length: {}", udp.length());
        }
        Some(TransportSlice::Icmpv4(_)) => {
            println!("IMCPv4 packet");
        }
        Some(TransportSlice::Icmpv6(_)) => {
            println!("ICMPv6 packet");
        }
        Some(TransportSlice::Unknown(u)) => {
            println!("Unknown transport protocol: {}", u);
        }
        None => println!("No transport layer found"),
    }

    //analyze payload if present
    let payload = &packet.payload;
    if !payload.is_empty() {
        println!("Payload: {} bytes", payload.len());

        //print the first few bytes of the payload
        let preview_len = std::cmp::min(16, payload.len());
        print!("Preview: ");
        for byte in &payload[0..preview_len] {
            print!("{:02x} ", byte);
        }
        println!();
    } else {
        println!("Payload: empty");
    }
}



