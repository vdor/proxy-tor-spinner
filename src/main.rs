use futures::stream::Stream;
use futures::future::Future;

use tokio_core::reactor::Core;
use tokio_core::net::{TcpListener, TcpStream};
#[allow(deprecated)]
use tokio_core::io::Io;
#[allow(deprecated)]
use tokio_core::io::copy;

use torproxy::{TorProxyManager, TorProxyPort};
use argparse::{ArgumentParser, Store};


fn main() {
    let mut containers_count = 5;
    let mut socks_port = 1523;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Tor porxy manager, to make requests from different IPs");
        ap.refer(&mut containers_count).add_option(&["-c", "--containers-count"], Store, "Count of containers to run");
        ap.refer(&mut socks_port).add_option(&["-p", "--socks-port"], Store, "Socks port");
        ap.parse_args_or_exit();
    }
    let mut tor_proxy_manager = TorProxyManager::new(Some(containers_count));
    
    tor_proxy_manager.start().unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let addr = format!("127.0.0.1:{}", socks_port).parse().unwrap();

    let sock = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on 127.0.0.1:{}", sock.local_addr().unwrap().port());

    let server = sock.incoming().for_each(|data| {
            let client_stream: TcpStream = data.0;

            #[allow(deprecated)]
            let (client_read, client_write) = client_stream.split();
            let proxy_port: &TorProxyPort = tor_proxy_manager.get_next_port().unwrap();
            let tor_proxy_addr = format!("0.0.0.0:{}", proxy_port.proxy_port).parse().unwrap();

            let send_data = TcpStream::connect(&tor_proxy_addr, &handle).and_then(|server_stream: TcpStream| {
                #[allow(deprecated)]
                let (server_read, server_write) = server_stream.split();

                #[allow(deprecated)]
                let client_to_server = copy(client_read, server_write);
                #[allow(deprecated)]
                let server_to_client = copy(server_read, client_write);
                client_to_server.join(server_to_client)
            }).map(|(_client_to_server,_server_to_client)| {} ).map_err(|_err| {} );
            handle.spawn(send_data);
            proxy_port.change_circuit();
            Ok(())
    });
    core.run(server).unwrap();
}
