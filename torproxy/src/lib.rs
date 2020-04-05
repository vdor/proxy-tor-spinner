use shiplift::{ContainerOptions, PullOptions, Docker, Container};
use shiplift::rep::{ContainerCreateInfo};
use tokio::prelude::{Future, Stream};
use telnet::Telnet;


use port_scanner::local_port_available;

const MAX_CONTAINERS_RECOMMENDED: u16 = 5;
const TOR_CONTROL_PORT: u16 = 9051;
const TOR_PROXY_PORT: u16 = 9050;
const TOR_PROXY_DOCKER_IMAGE_NAME: &str = "dperson/torproxy";

type NetworkPort = u16;

// Range of ports to use for the program by tor clients
struct TorProxyPortRange {
    start: NetworkPort,
    end: NetworkPort,
}

// Proxy ports used bt tor clients
#[derive(Debug)]
pub struct TorProxyPort {
    pub control_port: NetworkPort,
    pub proxy_port: NetworkPort,
    pub is_used_by_proxy: bool,
    pub use_in_progress: bool,
}

impl TorProxyPort {
    pub fn change_circuit(&self) {
        let connection = Telnet::connect(("0.0.0.0", self.control_port), 256);
        match connection {
            Ok(mut connection) => {
                let message = "authenticate \"tor\"\n".as_bytes();
                let result = connection.write(message);
                match result {
                    Err(e) => {
                        println!("Error auth to change circuit: {:?}", e);
                    },
                    Ok(_) => {
                        let message = "SIGNAL NEWNYM\n".as_bytes();
                        let result = connection.write(message);

                        match result {
                            Err(e) => println!("Error signal to change circuit: {:?}", e),
                            _ => {},
                        }
                    },
                };
            },
            Err(e) => {
                println!("Error connection to control port: {:?}", e);
            },
        }
    }
}

// Used to manage tor proxy clients
pub struct TorProxyManager  {
    containers_count: u16,
    pub ports: Vec<TorProxyPort>,
    ports_range: TorProxyPortRange,
    next_available_port_index: usize,
    docker: Docker,
    containers: Vec<ContainerCreateInfo>,
}

impl TorProxyManager {
    // Create new instance of manager
    pub fn new(containers_count: Option<u16>) -> Self {
        let containers_count = match containers_count {
            Some(count) => count,
            None => MAX_CONTAINERS_RECOMMENDED,
        };
        Self{
            containers_count,
            ports: Vec::with_capacity(containers_count as usize),
            ports_range: TorProxyPortRange{ start: 9000, end: 9100},
            docker: Docker::new(),
            containers: Vec::with_capacity(containers_count as usize),
            next_available_port_index: 0,
        }
    }

    // Starts tor clients
    pub fn start(&mut self) -> Result<&Self, String> {
        if self.containers_count > MAX_CONTAINERS_RECOMMENDED {
            println!("Too many containers. Recommended less then {:?}", MAX_CONTAINERS_RECOMMENDED);
        }
    
        println!("Starting Tor Proxy...");
    
        let ports_count_to_use = self.get_ports_count_to_use();
        let available_ports = self.search_available_ports(ports_count_to_use);

        if available_ports.len() < ports_count_to_use as usize {
            return Err(String::from("Not enough available ports"));
        }

        self.set_ports(&available_ports);
        self.pull_image();
        self.create_containers();
        Ok(self)
    }

    pub fn stop(&self) {
        // Todo set default values
        self.delete_containers();
    }

    fn get_ports_count_to_use(&self) -> u16 {
        self.containers_count * 2
    }

    // Sets port range to use by manager
    pub fn set_ports_range(&self, start: NetworkPort, end: NetworkPort) -> Result<&Self, String> {
        if start > end {
            return Err(String::from("Start port can't be larger then end"));
        }

        if start == end {
            return Err(String::from("Start and end ports are equal"));
        }

        let ports_count = self.get_ports_count_to_use();

        if end - start < ports_count {
            return Err(String::from(format!("Not enough port range. Has to be more than {}", ports_count)));
        }

        Ok(self)
    }

    // Searches available ports and returns them
    fn search_available_ports(&self, count_ports_max: u16) -> Vec<u16> {
        let ports_count_max : usize = (self.ports_range.end - self.ports_range.start) as usize;
        let mut available_ports : Vec<u16> = Vec::with_capacity(ports_count_max);
        let mut count_ports_found = 0;

        for port in self.ports_range.start..self.ports_range.end {
            if local_port_available(port) {
                available_ports.push(port);
                count_ports_found += 1;

                if count_ports_found == count_ports_max {
                    break
                }
            }
        }

        available_ports
    }

    // Set ports to use by manager, by provided array
    // Sets only ports that will be used by mananger
    pub fn set_ports(&mut self, available_ports: &Vec<NetworkPort>) {
        self.ports.clear();
        let mut available_ports_index = 0;
        for _ in 0..self.containers_count {
            let control_port = available_ports.get(available_ports_index).unwrap();
            let proxy_port = available_ports.get(available_ports_index + 1).unwrap();
            available_ports_index += 2;
            self.ports.push(TorProxyPort{
                control_port: *control_port,
                proxy_port: *proxy_port,
                is_used_by_proxy: true,
                use_in_progress: false,
            });
        }
    }

    // Pulls tor proxy image
    fn pull_image(&self) {
        let fut = self.docker
            .images()
            .pull(&PullOptions::builder().image(TOR_PROXY_DOCKER_IMAGE_NAME).build())
            .for_each(|output| {
                println!("{:?}", output);
                Ok(())
            })
            .map_err(|e| eprintln!("Error: {:?}", e));
        tokio::run(fut);
    }

    // Creates a docker container with tor client
    fn create_container(&self, ports: &TorProxyPort) -> Result<ContainerCreateInfo, String> {
        let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        let fut = self.docker.containers().create(
            &ContainerOptions::builder(TOR_PROXY_DOCKER_IMAGE_NAME)
                .expose(TOR_CONTROL_PORT as u32, "tcp", ports.control_port as u32)
                .expose(TOR_PROXY_PORT as u32, "tcp", ports.proxy_port as u32)
                .env(vec!
                    [
                        "PASSWORD=tor",
                        "TOR_NewCircuitPeriod=3",
                        "TOR_EnforceDistinctSubnets=0",
                        "MaxCircuitDirtiness=1",
                        "NumEntryGuards=1",
                ])
                .build()
        )
            .map_err(|e| eprintln!("Error: {:?}", e));
        let container_info = runtime.block_on(fut).unwrap();
        let container = Container::new(&self.docker, &container_info.id);
        let container_start_fut = container.start().map_err(|e| eprintln!("Error: {:?}", e));
        tokio::run(container_start_fut);
        Ok(container_info)
    }

    // Creates tor proxy containers
    fn create_containers(&mut self) {
        for port in &self.ports {
            let container = self.create_container(port).unwrap();
            self.containers.push(container);
        }
    }

    fn delete_containers(&self) {
        let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
        for container in self.containers.iter() {
            let fut = self.docker
                .containers()
                .get(&container.id)
                .stop(None)
                .map_err(|e| eprintln!("Error: {:?}", e));

            runtime.block_on(fut).unwrap();
            let fut = self.docker
                .containers()
                .get(&container.id)
                .delete()
                .map_err(|e| eprintln!("Error: {:?}", e));
            runtime.block_on(fut).unwrap();
        }
    }

    pub fn get_next_port(&mut self) -> Option<&mut TorProxyPort> {
        // self.ports.get_mut(0)
        let current_index = self.next_available_port_index;

        if self.ports.len() - 1 > self.next_available_port_index {
            self.next_available_port_index += 1;
        } else {
            self.next_available_port_index = 0;
        }

        self.ports.get_mut(current_index)
    }
}


// fn main() {
//     let mut proxy = TorProxyManager::new(5);
//     proxy.start().unwrap();
// }
