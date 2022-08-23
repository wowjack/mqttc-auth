use minimq::{Minimq, QoS, Retain};

use embedded_nal::{self, IpAddr, Ipv4Addr};
use std_embedded_time::StandardClock;

#[test]
fn main() -> std::io::Result<()> {
    env_logger::init();

    let stack = std_embedded_nal::Stack::default();
    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut mqtt =
        Minimq::<_, _, 256, 16>::new(localhost, "", stack, StandardClock::default()).unwrap();

    // Use a keepalive interval for the client.
    mqtt.client().set_keepalive_interval(60).unwrap();

    let mut published = false;

    loop {
        mqtt.poll(|_client, _topic, _payload, _properties| {})
            .unwrap();

        if mqtt.client().is_connected() && !published && mqtt.client().can_publish(QoS::ExactlyOnce)
        {
            mqtt.client()
                .publish(
                    "data",
                    "Ping".as_bytes(),
                    QoS::ExactlyOnce,
                    Retain::NotRetained,
                    &[],
                )
                .unwrap();
            log::info!("Publishing message");
            published = true;
        }

        if published && mqtt.client().pending_messages(QoS::ExactlyOnce) == 0 {
            log::info!("Transmission complete");
            std::process::exit(0);
        }
    }
}
