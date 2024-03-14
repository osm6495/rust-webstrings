use clap::Parser;
use std::collections::HashSet;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Mutex;

mod js;
mod links;
use links::{get_links, get_script_sources};
mod http;
mod secrets;

#[derive(Parser, Debug)]
#[command(author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"), about = env!("CARGO_PKG_DESCRIPTION"), long_about = None)]
struct Args {
    /// Include sources of findings
    #[arg(short = 'c', long = "cite")]
    cite: bool,

    /// Include noisy regex patterns
    #[arg(short = 'a', long = "all")]
    all: bool,

    //TODO add output file functionality
    /// Number of concurrent requests, with 10 being the default
    #[arg(short = 't', long = "threads", default_value = "10")]
    threads: usize,

    /// Debug mode
    #[arg(short = 'd', long = "debug", default_value = "false")]
    debug: bool,

    /// Print all URLs instead of secrets or strings
    #[arg(short = 'u', long = "urls", default_value = "false")]
    urls: bool,

    /// Find secrets with regex patterns rather than strings
    #[arg(short = 's', long = "secrets", default_value = "false")]
    secrets: bool,

    /// Use file instead of URL
    #[arg(short = 'f', long = "file")]
    file: Option<String>,

    /// URL to search
    url: Option<String>,
}

async fn process_url(
    url: &String,
    debug: bool,
    urls: bool,
    secrets: bool,
    cite: bool,
    noisy: bool,
) -> Vec<String> {
    let mut new_urls = Vec::new();

    let res = match http::get(url).await {
        Ok(res) => res,
        Err(e) => {
            if debug {
                eprintln!("[WARN] Failed to get {}: {}", url, e);
            }
            return new_urls;
        }
    };

    if !(res.status.is_success()) {
        if debug {
            eprintln!("[WARN] Failed to get {}: {}", url, res.status);
        }
        return new_urls;
    }

    if debug {
        eprintln!("[INFO] Url: {}", url);
        eprintln!("[INFO] Status: {}", res.status);
        //println!("Headers:\n{:#?}", res.headers);
        //println!("Body:\n{}", res.body);
    }

    if urls {
        for link in get_links(&res, url).iter() {
            println!("{}", link);
            new_urls.push(link.to_string());
        }
    } else {
        if secrets {
            secrets::get_header_secrets(&res, noisy)
                .iter()
                .for_each(|link| {
                    if cite {
                        println!("{} (Location: {})", link, url); //TODO Find a way to remove duplicate findings, despite being found in different tasks
                    } else {
                        println!("{}", link)
                    }
                });
            secrets::get_secrets(&res, noisy).iter().for_each(|link| {
                if cite {
                    println!("{} (Location: {})", link, url);
                } else {
                    println!("{}", link)
                }
            });
        } else {
            if url.ends_with(".js") {
                js::extract_strings(&res.body).iter().for_each(|string| {
                    if cite {
                        println!("{} (Location: {})", string, url);
                    } else {
                        println!("{}", string);
                    }
                });
            }
            js::get_scripts(&res)
                .expect("Failed to get scripts")
                .iter()
                .for_each(|script| {
                    js::extract_strings(script).iter().for_each(|string| {
                        if cite {
                            println!("{} (Location: {})", string, url);
                        } else {
                            println!("{}", string);
                        }
                    });
                });
        }

        for link in get_links(&res, url).iter() {
            new_urls.push(link.to_string());
        }

        for source in get_script_sources(&res, url)
            .expect("get_script_sources error")
            .iter()
        {
            new_urls.push(source.to_string());
        }
    }

    new_urls
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Create a multi-producer single-consumer (mpsc) channel for the URLs
    let (url_sender, mut url_receiver) = tokio::sync::mpsc::channel(100);
    let url_sender = Arc::new(Mutex::new(url_sender));
    let sent_messages = Arc::new(Mutex::new(HashSet::new()));

    let urls = if let Some(file) = args.file {
        std::fs::read_to_string(file)
            .expect("Failed to read file")
            .lines()
            .map(|line| {
                if line.starts_with("http://") || line.starts_with("https://") {
                    line.to_string()
                } else {
                    format!("https://{}", line)
                }
            })
            .collect::<Vec<_>>()
    } else if let Some(url) = args.url {
        vec![
            if url.starts_with("http://") || url.starts_with("https://") {
                url
            } else {
                format!("https://{}", url)
            },
        ]
    } else {
        // Print help message if no URL or file is provided
        match Args::try_parse_from(["webscan", "-h"]) {
            Ok(_) => return,
            Err(e) => e.exit(),
        };
    };

    let url_sender_clone = Arc::clone(&url_sender);
    for url in urls {
        {
            let sender = url_sender.lock().await;
            let mut sent_messages = sent_messages.lock().await;
            if !sent_messages.contains(url.as_str()) {
                sent_messages.insert(url.clone());
                match sender.send(url).await {
                    Ok(_) => (),
                    Err(e) => eprintln!("Unable to send url to channel: {}", e),
                }
            } else {
                continue;
            }
        }
    }
    //Drop the channel now that the original urls are done being sent
    drop(url_sender_clone);

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let active_tasks = Arc::new(AtomicUsize::new(0));

    loop {
        tokio::time::sleep(Duration::from_millis(100)).await; //Avoid race conditions
        let url_option = url_receiver.try_recv();
        if active_tasks.load(Ordering::Relaxed) == 0 && url_option.is_err() {
            drop(url_sender);
            break;
        }

        match url_option {
            Ok(url) => {
                let url_sender = Arc::clone(&url_sender);
                let active_tasks = Arc::clone(&active_tasks);
                let sent_messages = Arc::clone(&sent_messages);

                active_tasks.fetch_add(1, Ordering::Relaxed);
                let task = tokio::spawn(async move {
                    let new_urls = process_url(
                        &url,
                        args.debug,
                        args.urls,
                        args.secrets,
                        args.cite,
                        args.all,
                    )
                    .await;
                    if new_urls.is_empty() {
                        active_tasks.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        for new_url in new_urls {
                            {
                                let sender = url_sender.lock().await;
                                let mut sent_messages = sent_messages.lock().await;
                                if !sent_messages.contains(new_url.as_str()) {
                                    sent_messages.insert(new_url.clone());
                                    match sender.send(new_url).await {
                                        Ok(_) => (),
                                        Err(e) => {
                                            eprintln!("Task unable to send url to channel: {}", e)
                                        }
                                    }
                                } else {
                                    continue;
                                }
                            }
                        }

                        active_tasks.fetch_sub(1, Ordering::Relaxed);
                    }
                });

                tasks.push(task);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                // Wait a bit and try again
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                eprintln!("Error: Channel disconnected");
                break;
            }
        }
    }

    for task in tasks {
        match task.await {
            Ok(_) => (),
            Err(e) => eprintln!("A task panicked: {:?}", e),
        }
    }
}
