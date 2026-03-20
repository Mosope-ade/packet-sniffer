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
            return ok(());
        }
    };
    println!("Capturing on device {}", device name);

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

                orintln!("\n[Packet #{}] {} bytes", packet_count, packet.header.len);

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



}



