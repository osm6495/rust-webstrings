use clap::Parser;
use dashmap::{DashMap, DashSet};
use spinoff::{spinners, Color, Spinner};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::Duration;

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

    /// Depth of scan, with 255 being unlimited
    #[arg(long = "depth", default_value = "2")]
    depth: u8,

    /// Number of concurrent requests
    #[arg(short = 't', long = "threads", default_value = "25")]
    threads: usize,

    /// Debug mode
    #[arg(short = 'd', long = "debug", default_value = "false")]
    debug: bool,

    /// Measure duration of scan
    #[arg(long = "timer")]
    timer: bool,

    /// Don't print the loading spinner for cleaner output
    #[arg(long = "no-spinner")]
    no_spinner: bool,

    /// Print all URLs instead of secrets or strings
    #[arg(short = 'u', long = "urls", default_value = "false")]
    urls: bool,

    /// Find secrets with regex patterns rather than strings
    #[arg(short = 's', long = "secrets", default_value = "false")]
    secrets: bool,

    /// Don't search for strings, only urls or secrets
    #[arg(long = "no-strings", default_value = "false")]
    no_strings: bool,

    /// Use file instead of URL
    #[arg(short = 'f', long = "file")]
    file: bool,

    /// URL to search
    url: Option<String>,
}

struct WorkerOptions {
    debug: bool,
    urls: bool,
    secrets: bool,
    no_strings: bool,
    cite: bool,
    noisy: bool,
    depth: u8,
}

async fn process_url(
    url: &String,
    options: &WorkerOptions,
    client: &reqwest::Client,
    output: tokio::sync::mpsc::Sender<String>,
    url_map: Arc<DashMap<String, u8>>,
    depth: u8,
) {
    let res = match http::get(url, client).await {
        Ok(res) => res,
        Err(e) => {
            if options.debug {
                let message = format!("[WARN] Failed to get {}: {}", url, e);
                output
                    .clone()
                    .send(message)
                    .await
                    .expect("Worker failed to send output");
            }
            return;
        }
    };

    if !(res.status.is_success()) {
        if options.debug {
            println!("[WARN] Failed to get {}: {}", url, res.status);
        }
        return;
    }

    // Get URLs from the page and sources
    for link in get_links(&res, url).iter() {
        if options.urls {
            let message = format!("{}", link);
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
        // options.depth is also + 1 to be inclusive of max value
        if (depth + 1) < (options.depth) || options.depth == 255 {
            url_map.entry(link.clone()).or_insert(depth + 1); // Add non-duplicate URLs to hashmap for orchestrator thread to assign to workers, but only if not at depth
        }
    }
    for source in get_script_sources(&res, url)
        .expect("get_script_sources error")
        .iter()
    {
        // options.depth is also + 1 to be inclusive of max value
        if (depth + 1) < (options.depth + 1) || options.depth == 255 {
            url_map.entry(source.clone()).or_insert(depth + 1); // Add non-duplicate URLs to hashmap for orchestrator thread to assign to workers, but only if not at depth
        }
    }

    // Get either secrets or strings
    if options.secrets {
        for link in secrets::get_header_secrets(&res, options.noisy) {
            let message: String;
            if options.cite {
                message = format!("{} (Location: {})", link, url);
            } else {
                message = format!("{}", link);
            }
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
        for link in secrets::get_secrets(&res, options.noisy) {
            let message: String;
            if options.cite {
                message = format!("{} (Location: {})", link, url);
            } else {
                message = format!("{}", link);
            }
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
    }
    if !options.no_strings {
        if url.ends_with(".js") {
            for string in js::extract_strings(&res.body) {
                let message: String;
                if options.cite {
                    message = format!("{} (Location: {})", string, url);
                } else {
                    message = format!("{}", string);
                }
                output
                    .clone()
                    .send(message)
                    .await
                    .expect("Worker failed to send output");
            }
        }
        for string in js::get_scripts(&res)
            .expect("Failed to get scripts")
            .iter() // Assuming get_scripts returns a Vec or similar collection
            .flat_map(|script| js::extract_strings(script))
        {
            let message: String;
            if options.cite {
                message = format!("{} (Location: {})", string, url);
            } else {
                message = format!("{}", string);
            }
            output
                .clone()
                .send(message)
                .await
                .expect("Worker failed to send output");
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let start = Instant::now();

    // The URL map actually uses the depth as a way to mark URLs as previously scanned using a 255 value.
    let url_map: Arc<DashMap<String, u8>> = Arc::new(DashMap::new()); // Using a concurrent hashmap to avoid duplicates and race conditions
    let (output_sender, mut output_receiver) = tokio::sync::mpsc::channel(100);
    let finding_map: Arc<DashSet<String>> = Arc::new(DashSet::new());

    // Parse input and add to url_map
    if args.file {
        if let Some(path) = args.url {
            // First arg (usually a single url) is now expecting a filepath
            std::fs::read_to_string(path)
                .expect("Failed to read file")
                .lines()
                .map(|line| {
                    if line.starts_with("http://") || line.starts_with("https://") {
                        line.to_string()
                    } else {
                        format!("https://{}", line)
                    }
                })
                .for_each(|url| {
                    url_map.insert(url, 0);
                });
        };
    } else if let Some(url) = args.url {
        if url.starts_with("http://") || url.starts_with("https://") {
            url_map.insert(url, 0);
        } else {
            url_map.insert(format!("https://{}", url), 1);
        }
    } else {
        // Print help message if no URL or file is provided
        match Args::try_parse_from(["webscan", "-h"]) {
            Ok(_) => return,
            Err(e) => e.exit(),
        };
    };

    // Create a single producer single concumer channel for each thread that the orchestration thread will use to give them tasks
    let mut senders = Vec::with_capacity(args.threads);
    let mut receivers: Vec<tokio::sync::mpsc::Receiver<(String, u8)>> =
        Vec::with_capacity(args.threads);
    for _ in 0..args.threads {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        senders.push(tx);
        receivers.push(rx);
    }

    // Spawn a thread for each channel (args.threads num of threads), and have them process any URLs sent the the channels until the channels are closed
    for (_, mut receiver) in receivers.into_iter().enumerate() {
        let url_map_clone = url_map.clone();
        let output_sender_clone = output_sender.clone();
        let options = WorkerOptions {
            debug: args.debug,
            urls: args.urls,
            secrets: args.secrets,
            no_strings: args.no_strings,
            cite: args.cite,
            noisy: args.all,
            depth: args.depth,
        };
        let http_client = reqwest::Client::new();
        tokio::spawn(async move {
            while let Some((url, depth)) = receiver.recv().await {
                if url == "close_thread" {
                    break;
                }
                if args.debug {
                    println!("[INFO] Depth: {}, URL: {}", depth, url);
                }
                let url_clone = url.clone();
                process_url(
                    &url_clone,
                    &options,
                    &http_client,
                    output_sender_clone.clone(),
                    url_map_clone.clone(),
                    depth,
                )
                .await;
            }
            drop(output_sender_clone);
        });
    }

    // Output thread collects output and stores in hashset to remove duplicates
    let finding_map_clone = Arc::clone(&finding_map);
    let output_thread = tokio::spawn(async move {
        while let Some(output) = output_receiver.recv().await {
            finding_map_clone.insert(output);
        }
    });

    // Make a loading spinner before assigning tasks to workers, but only if not disabled with the CLI flag
    let sp = if args.no_spinner {
        None
    } else {
        Some(Spinner::new(spinners::Arc, "Scanning...", Color::White))
    };

    // Orchestration thread will send URLs to each thread and close the channels after the URLs map has been empty for a series of sleep periods
    let mut sleep_periods = 0;
    let senders_clone = senders.clone();
    let mut senders_cycle = senders_clone.into_iter().cycle();
    loop {
        let urls_to_process: Vec<(String, u8)> = url_map
            .iter()
            .filter(|entry| *entry.value() != 255)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        if !urls_to_process.is_empty() {
            for (url, depth) in urls_to_process {
                url_map.insert(url.clone(), 255);
                if let Some(sender) = senders_cycle.next() {
                    // Directly await the send operation, handling potential error
                    let send_result = sender.send((url.to_string(), depth)).await;
                    if let Err(e) = send_result {
                        eprintln!("Failed to send URL to worker: {}", e);
                    }
                }
                sleep_periods = 0;
            }
        } else {
            sleep_periods += 1;
            let sleep_duration = Duration::from_secs(1);
            tokio::time::sleep(sleep_duration).await;
        }

        // If it reaches 5 sleep periods with no URLs, close the worker threads and exit.
        if sleep_periods >= 5 {
            for sender in senders {
                let _ = sender
                    .send(("close_thread".to_string(), 0))
                    .await
                    .expect("Failed to send close_thread");
            }
            drop(output_sender);
            break;
        }
    }

    // Stop loading spinner before output, assuming it's not disabled with the CLI flag
    if let Some(mut spinner) = sp {
        spinner.stop();
    }

    output_thread.await.expect("Output thread failed");
    for finding in finding_map.iter() {
        // TODO add output format functionality
        println!("{}", *finding);
    }

    if args.timer {
        let elapsed = start.elapsed();
        println!("Elapsed time: {:?}", elapsed);
    }
}
